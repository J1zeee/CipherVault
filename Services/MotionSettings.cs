using System.Windows;

namespace CipherVault.Services;

/// <summary>
/// How long transitions run, and whether they run at all.
///
/// Durations are short on purpose: a password manager is opened to retrieve a
/// password quickly, not to be admired. Anything much over a quarter of a second
/// starts being felt as waiting.
///
/// Users who turn animation off in Windows are often doing it for motion
/// sensitivity, or working over a remote session where animation is painful. An
/// app that ignores that setting is not merely unfashionable, so every duration
/// passes through <see cref="Scale(TimeSpan)"/> rather than being used directly.
/// </summary>
public static class MotionSettings
{
    public static readonly TimeSpan ScreenTransition = TimeSpan.FromMilliseconds(200);
    public static readonly TimeSpan PanelTransition = TimeSpan.FromMilliseconds(170);
    public static readonly TimeSpan DialogTransition = TimeSpan.FromMilliseconds(160);
    public static readonly TimeSpan DetailCrossFade = TimeSpan.FromMilliseconds(170);
    public static readonly TimeSpan StrengthBar = TimeSpan.FromMilliseconds(250);

    public static bool AnimationsEnabled => SystemParameters.ClientAreaAnimation;

    public static TimeSpan Scale(TimeSpan duration) => Scale(duration, AnimationsEnabled);

    public static TimeSpan Scale(TimeSpan duration, bool animationsEnabled)
        => animationsEnabled ? duration : TimeSpan.Zero;
}
