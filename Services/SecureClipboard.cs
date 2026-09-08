using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace CipherVault.Services;

/// <summary>
/// Clipboard access for secrets. A plain Clipboard.SetText lands in Windows clipboard
/// history (Win+V) and in cloud clipboard sync, where the app's own clear timer cannot
/// reach it, so every copy carries the documented opt-out formats instead.
///
/// Clipboard calls fail whenever another process holds the clipboard open - clipboard
/// managers and RDP sessions do this routinely - so callers get a bool rather than an
/// exception that would take the whole app down.
/// </summary>
public static class SecureClipboard
{
    public const string ExcludeFromMonitorFormat = "ExcludeClipboardContentFromMonitorProcessing";
    public const string ClipboardHistoryFormat = "CanIncludeInClipboardHistory";
    public const string CloudClipboardFormat = "CanUploadToCloudClipboard";

    // A hash, not the value: remembering what was copied must not itself keep the
    // secret alive in the heap.
    private static byte[]? _lastCopyFingerprint;

    public static DataObject BuildPayload(string text)
    {
        var payload = new DataObject();
        payload.SetText(text ?? "");

        // Windows reads these as a DWORD; zero means "do not keep this".
        payload.SetData(ExcludeFromMonitorFormat, ZeroDword());
        payload.SetData(ClipboardHistoryFormat, ZeroDword());
        payload.SetData(CloudClipboardFormat, ZeroDword());

        return payload;
    }

    public static bool TrySetText(string text)
    {
        try
        {
            Clipboard.SetDataObject(BuildPayload(text), copy: true);
            RememberCopy(text);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Records that <paramref name="text"/> is what this app put on the clipboard.</summary>
    public static void RememberCopy(string text)
    {
        _lastCopyFingerprint = Fingerprint(text);
    }

    public static void ForgetCopy()
    {
        _lastCopyFingerprint = null;
    }

    /// <summary>True when the clipboard still holds the value this app last copied.</summary>
    public static bool IsRememberedContent(string? clipboardText)
    {
        if (_lastCopyFingerprint == null || string.IsNullOrEmpty(clipboardText))
            return false;

        return CryptographicOperations.FixedTimeEquals(_lastCopyFingerprint, Fingerprint(clipboardText));
    }

    /// <summary>
    /// Clears the clipboard only when it still holds this app's own copy. Clearing
    /// unconditionally destroyed whatever the user had copied since - the clear timer
    /// and app shutdown both used to do exactly that.
    /// </summary>
    public static bool TryClearOurs()
    {
        try
        {
            if (!Clipboard.ContainsText() || !IsRememberedContent(Clipboard.GetText()))
                return false;

            Clipboard.Clear();
            ForgetCopy();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] Fingerprint(string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        try
        {
            return SHA256.HashData(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static MemoryStream ZeroDword() => new MemoryStream(new byte[] { 0, 0, 0, 0 });
}
