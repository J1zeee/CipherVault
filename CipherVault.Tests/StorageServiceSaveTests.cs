using System.IO;
using CipherVault.Models;
using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class StorageServiceSaveTests : IDisposable
{
    private const string MasterPassword = "correct horse battery staple";

    private readonly string _dir;
    private readonly string _vaultDat;

    public StorageServiceSaveTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "CipherVaultTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _vaultDat = Path.Combine(_dir, "vault.dat");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    private static List<Credential> OneCredential(string title)
    {
        var cred = new Credential { Title = title, Password = "secret-" + title };
        return new List<Credential> { cred };
    }

    [Fact]
    public void SaveVault_KeepsPreviousVaultAsRecoverableBackup()
    {
        using var service = new StorageService(_dir);
        service.CreateVault(MasterPassword);

        service.SaveVault(OneCredential("first"));
        var contentAfterFirstSave = File.ReadAllBytes(_vaultDat);

        service.SaveVault(OneCredential("second"));

        Assert.True(File.Exists(_vaultDat + ".bak"), "no backup was written next to vault.dat");
        Assert.Equal(contentAfterFirstSave, File.ReadAllBytes(_vaultDat + ".bak"));
    }

    [Fact]
    public void SaveVault_LeavesNoTempFileBehind()
    {
        using var service = new StorageService(_dir);
        service.CreateVault(MasterPassword);

        service.SaveVault(OneCredential("first"));

        Assert.False(File.Exists(_vaultDat + ".tmp"));
    }

    [Fact]
    public void SaveVault_ContentStillDecryptsAfterAtomicWrite()
    {
        using var service = new StorageService(_dir);
        service.CreateVault(MasterPassword);

        service.SaveVault(OneCredential("github"));
        var loaded = service.LoadVault();

        Assert.Single(loaded);
        Assert.Equal("github", loaded[0].Title);
        Assert.Equal("secret-github", loaded[0].Password);
    }
}
