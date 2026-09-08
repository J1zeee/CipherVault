using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class VaultPathsTests
{
    private const string Root = @"C:\Users\tester\AppData\Local\CipherVault";
    private const string Personal = @"C:\Users\tester\AppData\Local\CipherVault\Personal";

    private static VaultPaths WithSelection()
    {
        var paths = new VaultPaths(Root);
        paths.SelectVault(Personal);
        return paths;
    }

    [Fact]
    public void ReloadingSettings_DoesNotForgetTheSelectedVault()
    {
        var paths = WithSelection();

        paths.SetRoot(Root);

        Assert.Equal(Personal, paths.CurrentVaultPath);
    }

    [Fact]
    public void ChangingRoot_DoesNotForgetTheSelectedVault()
    {
        var paths = WithSelection();

        paths.SetRoot(@"D:\Vaults");

        Assert.Equal(@"D:\Vaults", paths.RootPath);
        Assert.Equal(Personal, paths.CurrentVaultPath);
    }

    [Fact]
    public void DeleteTarget_IsTheSelectedVault()
    {
        var paths = WithSelection();

        Assert.True(paths.CanDeleteCurrentVault);
        Assert.Equal(Personal, paths.DeleteTargetPath);
    }

    [Fact]
    public void DeleteIsRefused_WhenNoVaultIsSelected()
    {
        var paths = new VaultPaths(Root);

        Assert.False(paths.CanDeleteCurrentVault);
    }

    [Fact]
    public void DeleteIsRefused_AfterTheSelectionIsCleared()
    {
        var paths = WithSelection();

        paths.ClearSelection();

        Assert.False(paths.CanDeleteCurrentVault);
        Assert.Null(paths.CurrentVaultPath);
    }

    [Fact]
    public void DeleteIsRefused_WhenSelectionIsTheRootItself()
    {
        var paths = new VaultPaths(Root);

        paths.SelectVault(Root);

        Assert.False(paths.CanDeleteCurrentVault);
    }

    [Fact]
    public void DeleteIsRefused_WhenSelectionIsTheRootWithDifferentCasingOrTrailingSlash()
    {
        var paths = new VaultPaths(Root);

        paths.SelectVault(@"c:\users\tester\appdata\local\ciphervault\");

        Assert.False(paths.CanDeleteCurrentVault);
    }

    [Fact]
    public void DeleteTargetPath_ThrowsWhenDeletionIsRefused()
    {
        var paths = new VaultPaths(Root);

        Assert.Throws<InvalidOperationException>(() => paths.DeleteTargetPath);
    }
}
