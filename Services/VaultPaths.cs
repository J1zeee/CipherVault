using System.IO;

namespace CipherVault.Services;

/// <summary>
/// Keeps the two paths the app used to conflate in a single field: the root folder
/// that holds every vault (configurable in settings) and the vault the user currently
/// has selected. Reloading settings must never silently retarget the current vault -
/// that is how "delete this vault" once pointed at the root and took every vault with it.
/// </summary>
public sealed class VaultPaths
{
    public VaultPaths(string rootPath)
    {
        RootPath = rootPath;
    }

    /// <summary>Folder that contains all vaults. Base for creating and importing.</summary>
    public string RootPath { get; private set; }

    /// <summary>Folder of the selected vault, or null when the user is at the vault list.</summary>
    public string? CurrentVaultPath { get; private set; }

    /// <summary>Vault folder if one is selected, otherwise the root - what to open storage on.</summary>
    public string ActivePath => CurrentVaultPath ?? RootPath;

    public void SetRoot(string rootPath)
    {
        RootPath = rootPath;
    }

    public void SelectVault(string vaultPath)
    {
        CurrentVaultPath = vaultPath;
    }

    public void ClearSelection()
    {
        CurrentVaultPath = null;
    }

    /// <summary>
    /// False when nothing is selected, or when the selection is the root itself -
    /// deleting the root would wipe every vault the user has.
    /// </summary>
    public bool CanDeleteCurrentVault =>
        CurrentVaultPath != null && !IsSamePath(CurrentVaultPath, RootPath);

    public string DeleteTargetPath
    {
        get
        {
            if (!CanDeleteCurrentVault)
                throw new InvalidOperationException("No individual vault is selected for deletion.");

            return CurrentVaultPath!;
        }
    }

    private static bool IsSamePath(string left, string right)
    {
        return string.Equals(Normalize(left), Normalize(right), StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalize(string path)
    {
        try
        {
            return Path.GetFullPath(path)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch
        {
            return path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
    }
}
