using System.IO;
using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class AppSettingsStoreTests : IDisposable
{
    private readonly string _dir;
    private readonly string _file;

    public AppSettingsStoreTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "CipherVaultTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _file = Path.Combine(_dir, "settings.json");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    [Fact]
    public void GetBool_ReturnsFallbackWhenNothingIsStored()
    {
        Assert.True(new AppSettingsStore(_dir).GetBool("loggingEnabled", true));
        Assert.False(new AppSettingsStore(_dir).GetBool("loggingEnabled", false));
    }

    [Fact]
    public void SetBool_SurvivesAcrossInstances()
    {
        new AppSettingsStore(_dir).SetBool("loggingEnabled", true);

        Assert.True(new AppSettingsStore(_dir).GetBool("loggingEnabled"));
    }

    [Fact]
    public void SetBool_False_IsStoredRatherThanTreatedAsAbsent()
    {
        new AppSettingsStore(_dir).SetBool("loggingEnabled", false);

        Assert.False(new AppSettingsStore(_dir).GetBool("loggingEnabled", defaultValue: true));
    }

    [Fact]
    public void SetString_RoundTrips()
    {
        new AppSettingsStore(_dir).SetString("vaultPath", @"D:\Vaults");

        Assert.Equal(@"D:\Vaults", new AppSettingsStore(_dir).GetString("vaultPath"));
    }

    [Fact]
    public void Writing_DoesNotDropKeysOwnedByOtherComponents()
    {
        File.WriteAllText(_file, "{\"language\":\"ru\"}");

        new AppSettingsStore(_dir).SetBool("loggingEnabled", true);

        Assert.Equal("ru", new AppSettingsStore(_dir).GetString("language"));
    }

    [Fact]
    public void CorruptSettingsFile_FallsBackToDefaultsInsteadOfThrowing()
    {
        File.WriteAllText(_file, "this is not json");

        var store = new AppSettingsStore(_dir);

        Assert.Null(store.GetString("vaultPath"));
        Assert.False(store.GetBool("loggingEnabled"));
    }
}
