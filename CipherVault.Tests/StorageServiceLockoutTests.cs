using System.IO;
using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class StorageServiceLockoutTests : IDisposable
{
    private const string MasterPassword = "correct horse battery staple";

    private static byte[] Password() => System.Text.Encoding.UTF8.GetBytes(MasterPassword);

    private const int MaxFailedAttempts = 5;

    private readonly string _dir;

    public StorageServiceLockoutTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "CipherVaultTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        using var service = new StorageService(_dir);
        service.CreateVault(Password());
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    private void FailLogin(int times)
    {
        using var service = new StorageService(_dir);
        for (var i = 0; i < times; i++)
            service.VerifyPassword(System.Text.Encoding.UTF8.GetBytes("wrong password"));
    }

    [Fact]
    public void FailedAttempts_SurviveNewServiceInstanceForSameVault()
    {
        FailLogin(2);

        using var reopened = new StorageService(_dir);

        Assert.Equal(2, reopened.FailedAttempts);
    }

    [Fact]
    public void Lockout_IsStillInEffectAfterReselectingTheVault()
    {
        FailLogin(MaxFailedAttempts);

        using var reopened = new StorageService(_dir);

        Assert.True(reopened.IsLockedOut(out var remaining), "reopening the vault cleared the lockout");
        Assert.True(remaining > 0);
    }

    [Fact]
    public void SuccessfulLogin_ClearsPersistedFailedAttempts()
    {
        FailLogin(2);

        using (var service = new StorageService(_dir))
        {
            var (success, _, _) = service.VerifyPassword(Password());
            Assert.True(success);
        }

        using var reopened = new StorageService(_dir);
        Assert.Equal(0, reopened.FailedAttempts);
    }
}
