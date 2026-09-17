using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CipherVault.Services;

/// <summary>
/// Argon2id derivation of the master key, computed by the P-H-C reference
/// implementation in argon2.dll (sources and build script under native/argon2).
///
/// The native library is used because it wipes what it touches: the Blake2b state
/// that absorbs the password, the pre-hash H0, the 128 MiB of blocks and its own
/// output buffer are all cleared with SecureZeroMemory before it returns. A managed
/// implementation (Konscious, used before) leaves such buffers on the GC heap as
/// unreachable garbage that nothing zeroes - the master password and the key both
/// showed up in a memory dump of the unlocked process.
///
/// Neither the password nor the key is copied on the managed side: the native code
/// reads the caller's span in place and writes straight into the key's buffer.
/// </summary>
public static class MasterKeyDerivation
{
    public const int KeySizeBytes = 32;

    private const int Iterations = 3;
    private const int MemoryKB = 131072;
    private const int Parallelism = 4;

    private const int ARGON2_OK = 0;

    // AssemblyDirectory only: argon2.dll must come from the application itself, never
    // from the working directory or PATH, where a planted copy could read the password.
    [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    private static extern unsafe int argon2id_hash_raw(
        uint t_cost, uint m_cost, uint parallelism,
        byte* pwd, nuint pwdlen,
        byte* salt, nuint saltlen,
        byte* hash, nuint hashlen);

    [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    private static extern IntPtr argon2_error_message(int error_code);

    /// <summary>
    /// Derives the master key. The password and salt belong to the caller: they are
    /// neither retained nor modified here, and zeroing them stays the caller's job.
    /// </summary>
    public static unsafe SecureBuffer Derive(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt)
    {
        // The reference implementation accepts an empty password; a master key must
        // never come from one.
        if (password.IsEmpty)
            throw new ArgumentException("Password must not be empty", nameof(password));

        var key = new SecureBuffer(KeySizeBytes);

        try
        {
            var output = key.GetWritableSpan();
            int result;

            fixed (byte* passwordPtr = password)
            fixed (byte* saltPtr = salt)
            fixed (byte* outputPtr = output)
            {
                result = argon2id_hash_raw(
                    Iterations, MemoryKB, Parallelism,
                    passwordPtr, (nuint)password.Length,
                    saltPtr, (nuint)salt.Length,
                    outputPtr, (nuint)output.Length);
            }

            if (result != ARGON2_OK)
            {
                var message = Marshal.PtrToStringAnsi(argon2_error_message(result));
                throw new CryptographicException($"Argon2id failed: {message} ({result})");
            }

            key.EndAccess();
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }
}
