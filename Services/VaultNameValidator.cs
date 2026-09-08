using System.IO;

namespace CipherVault.Services;

/// <summary>
/// A vault name becomes a directory name under the vaults root, so it has to survive
/// Path.Combine without escaping that root or tripping over a Windows file-name rule.
/// Names are rejected rather than silently rewritten: the user keeps control of what
/// their vault is called instead of finding a mangled name later.
/// </summary>
public static class VaultNameValidator
{
    public const int MaxLength = 64;

    private static readonly string[] ReservedNames =
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    public static bool IsValid(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;

        if (name.Length > MaxLength)
            return false;

        // A trailing dot or space is silently stripped by Windows, so the folder that
        // gets created would not match the name that was stored.
        if (name != name.TrimEnd('.', ' '))
            return false;

        if (name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            return false;

        // Path.GetInvalidFileNameChars covers the separators, but be explicit about the
        // traversal cases so the intent survives a platform change.
        if (name.Contains('/') || name.Contains('\\') || name == "." || name == "..")
            return false;

        var withoutExtension = Path.GetFileNameWithoutExtension(name);
        foreach (var reserved in ReservedNames)
        {
            if (string.Equals(withoutExtension, reserved, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        return true;
    }
}
