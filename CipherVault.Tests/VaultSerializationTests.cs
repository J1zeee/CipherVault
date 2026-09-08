using System.IO;
using System.Text;
using CipherVault.Models;
using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class VaultSerializationTests : IDisposable
{
    private const string MasterPassword = "correct horse battery staple";

    private readonly string _dir;

    public VaultSerializationTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "CipherVaultTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    private static byte[] Password() => Encoding.UTF8.GetBytes(MasterPassword);

    [Fact]
    public void CredentialsSurviveTheByteBasedSaveAndLoad()
    {
        var original = new Credential
        {
            Title = "Почта",
            Username = "j1zeee",
            Email = "user@example.com",
            Password = "p@ss \"w0rd\" \\ {}[]",
            Website = "https://example.com/a?b=c",
            Notes = "многострочная\nзаметка \U0001F510"
        };

        using var service = new StorageService(_dir);
        service.CreateVault(Password());
        service.SaveVault(new List<Credential> { original });

        var loaded = service.LoadVault();

        Assert.Single(loaded);
        Assert.Equal("Почта", loaded[0].Title);
        Assert.Equal("j1zeee", loaded[0].Username);
        Assert.Equal("user@example.com", loaded[0].Email);
        Assert.Equal("p@ss \"w0rd\" \\ {}[]", loaded[0].Password);
        Assert.Equal("https://example.com/a?b=c", loaded[0].Website);
        Assert.Equal("многострочная\nзаметка \U0001F510", loaded[0].Notes);
    }

    [Fact]
    public void AnEmptyVaultRoundTrips()
    {
        using var service = new StorageService(_dir);
        service.CreateVault(Password());

        service.SaveVault(new List<Credential>());

        Assert.Empty(service.LoadVault());
    }

    [Fact]
    public void StoredBytesNeverContainThePlaintext()
    {
        using var service = new StorageService(_dir);
        service.CreateVault(Password());
        service.SaveVault(new List<Credential>
        {
            new Credential { Title = "github", Password = "TOPSECRETVALUE" }
        });

        var raw = File.ReadAllBytes(Path.Combine(_dir, "vault.dat"));

        Assert.DoesNotContain("TOPSECRETVALUE", Encoding.UTF8.GetString(raw));
        Assert.DoesNotContain("github", Encoding.UTF8.GetString(raw));
    }

    [Fact]
    public void VerifyPasswordDoesNotConsumeTheCallersBuffer()
    {
        using var service = new StorageService(_dir);
        service.CreateVault(Password());

        var password = Password();
        service.VerifyPassword(password);

        Assert.Equal(Password(), password);
    }

    [Fact]
    public void CreateVaultDoesNotConsumeTheCallersBuffer()
    {
        using var service = new StorageService(_dir);

        var password = Password();
        service.CreateVault(password);

        Assert.Equal(Password(), password);
    }
}
