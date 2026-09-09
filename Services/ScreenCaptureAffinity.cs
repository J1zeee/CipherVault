namespace CipherVault.Services;

/// <summary>
/// Which WDA_* value SetWindowDisplayAffinity should be given.
///
/// Kept apart from the P/Invoke so the decision itself is testable: the call
/// cannot be exercised in a test, but choosing the wrong value silently leaves
/// the vault visible to screenshots.
/// </summary>
public static class ScreenCaptureAffinity
{
    public const uint None = 0x00000000;
    public const uint Monitor = 0x00000001;
    public const uint ExcludeFromCapture = 0x00000011;

    public static uint For(bool protectionEnabled, bool excludeFromCaptureSupported)
    {
        if (!protectionEnabled)
        {
            return None;
        }

        // WDA_EXCLUDEFROMCAPTURE needs Windows 10 2004 (build 19041). Older builds
        // get WDA_MONITOR: capture APIs still see black, only DWM thumbnails leak.
        return excludeFromCaptureSupported ? ExcludeFromCapture : Monitor;
    }
}
