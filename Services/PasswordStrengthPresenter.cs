namespace CipherVault.Services;

/// <summary>
/// Turns the score from <see cref="PasswordGenerator.AnalyzeStrength"/> into what the
/// strength meter shows.
///
/// This exists because the screen and the model used to disagree: the meter collapsed
/// the score into four buckets while AnalyzeStrength reports five, so a password the
/// model called "Strong" was labelled "Good" on screen, and the VeryStrong
/// localization key was never used at all. The buckets here are the model's.
/// </summary>
public static class PasswordStrengthPresenter
{
    public readonly record struct Presentation(string LocalizationKey, int FillPercent);

    public static Presentation Describe(int score)
    {
        var clamped = Math.Clamp(score, 0, 100);

        return clamped switch
        {
            >= 80 => new Presentation("VeryStrong", 100),
            >= 60 => new Presentation("Strong", 80),
            >= 40 => new Presentation("Good", 60),
            >= 20 => new Presentation("Fair", 40),
            _ => new Presentation("Weak", 20)
        };
    }
}
