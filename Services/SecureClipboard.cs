using System.IO;
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
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static bool TryClear()
    {
        try
        {
            Clipboard.Clear();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static MemoryStream ZeroDword() => new MemoryStream(new byte[] { 0, 0, 0, 0 });
}
