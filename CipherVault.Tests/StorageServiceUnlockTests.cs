using System.IO;
using System.Text.Json;
using CipherVault.Models;
using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class StorageServiceUnlockTests : IDisposable
{
    private const string MasterPassword = "correct horse battery staple";

    private static byte[] Password() => System.Text.Encoding.UTF8.GetBytes(MasterPassword);


    private readonly string _dir;

    public StorageServiceUnlockTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "CipherVaultTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);

        using var service = new StorageService(_dir);
        service.CreateVault(Password());
        service.SaveVault(new List<Credential> { new Credential { Title = "github", Password = "s3cret" } });
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    private void SetStoredVaultVersion(int version)
    {
        var path = Path.Combine(_dir, "config.json");
        var config = JsonSerializer.Deserialize<VaultConfig>(File.ReadAllText(path))!;
        config.Version = version;
        File.WriteAllText(path, JsonSerializer.Serialize(config));
    }

    [Fact]
    public void VerifyPassword_LeavesTheVaultOpenSoNoSecondKeyDerivationIsNeeded()
    {
        using var service = new StorageService(_dir);

        var (success, _, _) = service.VerifyPassword(Password());

        Assert.True(success);
        Assert.True(service.IsVaultOpen, "unlocking still requires a second Argon2 pass to open the vault");
    }

    [Fact]
    public void VerifyPassword_ReadsTheVaultWithoutAnyFurtherSetup()
    {
        using var service = new StorageService(_dir);
        service.VerifyPassword(Password());

        var loaded = service.LoadVault();

        Assert.Single(loaded);
        Assert.Equal("github", loaded[0].Title);
        Assert.Equal("s3cret", loaded[0].Password);
    }

    [Fact]
    public void VerifyPassword_RefusesAVaultWrittenByANewerVersion()
    {
        SetStoredVaultVersion(99);
        using var service = new StorageService(_dir);

        Assert.Throws<InvalidOperationException>(() => service.VerifyPassword(Password()));
    }

    [Fact]
    public void VerifyPassword_StillRejectsTheWrongPassword()
    {
        using var service = new StorageService(_dir);

        var (success, _, _) = service.VerifyPassword(System.Text.Encoding.UTF8.GetBytes("not the password"));

        Assert.False(success);
        Assert.False(service.IsVaultOpen);
    }
}
