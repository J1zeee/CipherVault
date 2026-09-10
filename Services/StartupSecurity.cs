#if RELEASE
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace CipherVault;

/// <summary>
/// Best-effort process hardening applied at application start, compiled into
/// Release builds only so that Debug remains easy to run and debug.
/// </summary>
internal static class StartupSecurity
{
    private const string SingleInstanceMutexName = @"Global\CipherVault.SingleInstance";
    private const string SingleInstanceMutexFallbackName = @"Local\CipherVault.SingleInstance";
    private const int ProcessAslrPolicy = 1;
    private const int ProcessStrictHandleCheckPolicy = 3;
    private const int ProcessExtensionPointDisablePolicy = 6;
    private const int ProcessImageLoadPolicy = 10;
    private const int ProcessChildProcessPolicy = 13;
    private const int ProcessDebugPortInformation = 7;
    private const int ProcessDebugObjectHandleInformation = 30;
    private const uint AslrPolicyBottomUpRandomization = 0x1;
    private const uint AslrPolicyForceRelocateImages = 0x2;
    private const uint AslrPolicyHighEntropy = 0x4;
    private const uint ImageLoadNoRemoteImages = 0x1;
    private const uint ImageLoadNoLowMandatoryLabelImages = 0x2;
    private const uint ChildProcessPolicyNoChildProcess = 0x1;
    private const uint StrictHandleCheckRaiseExceptionOnInvalidReference = 0x1;
    private const uint StrictHandleCheckExceptionsPermanentlyEnabled = 0x2;
    private const uint ExtensionPointDisableAllExtensionPoints = 0x1;

    private static Mutex? _singleInstanceMutex;

    private enum MutexAcquireResult
    {
        Owned,
        Busy,
    }

    [DllImport("kernel32.dll")]
    private static extern bool SetProcessMitigationPolicy(
        int mitigationPolicy,
        ref uint flags,
        int length);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll")]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr process, out bool present);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr process,
        int informationClass,
        out IntPtr information,
        int length,
        out int bytes);

    internal static void EnsureSingleInstance()
    {
        MutexAcquireResult result;
        try
        {
            result = AcquireMutex(SingleInstanceMutexName, out _singleInstanceMutex);
            if (result == MutexAcquireResult.Busy)
            {
                // Nonzero exit code so a "second instance attempted" can be told
                // apart from a normal close by scripts and shortcuts.
                Environment.Exit(1);
            }

            return;
        }
        catch (UnauthorizedAccessException)
        {
            // Creating Global\ kernel objects requires SeCreateGlobalPrivilege,
            // which standard accounts may not have; fall back to the per-session
            // namespace so the app still starts.
        }

        try
        {
            result = AcquireMutex(SingleInstanceMutexFallbackName, out _singleInstanceMutex);
        }
        catch (UnauthorizedAccessException)
        {
            // Neither namespace is usable; refuse to run instead of crashing with
            // an unexplained stack trace while two instances could race the vault.
            Environment.Exit(1);
            return;
        }

        if (result == MutexAcquireResult.Busy)
        {
            Environment.Exit(1);
        }
    }

    private static MutexAcquireResult AcquireMutex(string name, out Mutex mutex)
    {
        bool createdNew;
        try
        {
            mutex = new Mutex(true, name, out createdNew);
        }
        catch (AbandonedMutexException)
        {
            // A few runtimes surface an abandoned predecessor from the constructor
            // itself; re-create without initial ownership and acquire it below.
            // On .NET 8 the abandon is only reported by WaitOne(0), which the
            // sequence below already treats as owned.
            mutex = new Mutex(false, name, out createdNew);
            createdNew = false;
        }

        if (createdNew)
        {
            return MutexAcquireResult.Owned;
        }

        try
        {
            // An abandoned predecessor makes WaitOne(0) throw and hands ownership
            // to this thread; treat that as owning it.
            if (mutex.WaitOne(0))
            {
                return MutexAcquireResult.Owned;
            }
        }
        catch (AbandonedMutexException)
        {
            return MutexAcquireResult.Owned;
        }

        return MutexAcquireResult.Busy;
    }

    internal static bool DetectDebugger()
    {
        if (Debugger.IsAttached)
        {
            return true;
        }

        // The pseudo-handle (-1) returned by GetCurrentProcess is always valid and
        // is not owned by a managed Process object, so it cannot be invalidated by
        // the garbage collector mid-check.
        IntPtr process = GetCurrentProcess();

        if (IsDebuggerPresent())
        {
            return true;
        }

        if (CheckRemoteDebuggerPresent(process, out bool remote) && remote)
        {
            return true;
        }

        IntPtr value = IntPtr.Zero;
        if (NtQueryInformationProcess(process, ProcessDebugPortInformation, out value, IntPtr.Size, out _) >= 0
            && value != IntPtr.Zero)
        {
            return true;
        }

        value = IntPtr.Zero;
        if (NtQueryInformationProcess(process, ProcessDebugObjectHandleInformation, out value, IntPtr.Size, out _) >= 0
            && value != IntPtr.Zero)
        {
            // The debug object handle is duplicated into this process and must be
            // released explicitly, otherwise every check leaks a kernel handle.
            CloseHandle(value);
            return true;
        }

        return false;
    }

    internal static void ApplyMitigationPolicy()
    {
        // The strict "Microsoft-signed images only" signature policy would block
        // legitimate third-party injectors such as the NVIDIA overlay
        // (nvspcap64.dll), which makes Windows report STATUS_INVALID_IMAGE_HASH
        // (0xC0000428) at process start. Instead: forced ASLR relocation,
        // remote/low-integrity image blocking, DEP left to the OS (always on for
        // 64-bit processes), and a strict child-process ban. The ban forbids every
        // child process from this one, including shell launches - the clickable
        // link feature was removed for that reason, and any future WebView2 or
        // auto-updater component would hit ERROR_CHILD_PROCESS_BLOCKED too.
        SetMitigation(ProcessAslrPolicy, AslrPolicyBottomUpRandomization | AslrPolicyForceRelocateImages | AslrPolicyHighEntropy);
        SetMitigation(ProcessImageLoadPolicy, ImageLoadNoRemoteImages | ImageLoadNoLowMandatoryLabelImages);
        SetMitigation(ProcessChildProcessPolicy, ChildProcessPolicyNoChildProcess);
        // Strict handle checks turn invalid-handle use into a hard exception rather
        // than a silent no-op, catching corrupted or reused handles early. The
        // "permanently enabled" bit is not optional decoration: verified on
        // Windows 10 26100 that SetProcessMitigationPolicy rejects bit 0 alone
        // (returns FALSE, nothing applies) and accepts only 0x1|0x2 together.
        // Extension points cover AppInit_Dlls, Winsock LSPs and similar vectors.
        SetMitigation(ProcessStrictHandleCheckPolicy,
            StrictHandleCheckRaiseExceptionOnInvalidReference | StrictHandleCheckExceptionsPermanentlyEnabled);
        SetMitigation(ProcessExtensionPointDisablePolicy, ExtensionPointDisableAllExtensionPoints);
    }

    private static void SetMitigation(int policy, uint flags)
    {
        // Best-effort: machinery without support for a given policy is ignored.
        SetProcessMitigationPolicy(policy, ref flags, sizeof(uint));
    }

    internal static void ExitWithJitter()
    {
        // Soft anti-analysis: exit after a short randomized pause instead of
        // instantly, so a debugger cannot simply patch over the check.
        Thread.Sleep(Random.Shared.Next(1000, 4000));
    }
}
#endif