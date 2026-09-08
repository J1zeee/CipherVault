using System.IO;
using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class AuditServiceTests : IDisposable
{
    private readonly AuditService _audit;
    private readonly bool _loggingWasEnabled;

    public AuditServiceTests()
    {
        // AuditService is a process-wide singleton bound to the first path it is
        // given, so work with whatever path it actually holds.
        _audit = AuditService.Initialize(
            Path.Combine(Path.GetTempPath(), "CipherVaultTests_" + Guid.NewGuid().ToString("N")));
        Directory.CreateDirectory(Path.GetDirectoryName(_audit.LogFilePath)!);

        _loggingWasEnabled = AuditService.LoggingEnabled;
        AuditService.LoggingEnabled = true;
    }

    public void Dispose()
    {
        AuditService.LoggingEnabled = _loggingWasEnabled;
        try { File.Delete(_audit.LogFilePath); } catch { }
    }

    private string ReadLog() => File.Exists(_audit.LogFilePath) ? File.ReadAllText(_audit.LogFilePath) : "";

    [Fact]
    public void CredentialEventsAreStillRecorded()
    {
        _audit.LogCredentialAdded();
        _audit.LogCredentialModified();
        _audit.LogCredentialDeleted();

        var log = ReadLog();

        Assert.Contains("CredentialAdded", log);
        Assert.Contains("CredentialModified", log);
        Assert.Contains("CredentialDeleted", log);
    }

    [Fact]
    public void CredentialEventsCarryNoCredentialText()
    {
        _audit.LogCredentialAdded();
        _audit.LogCredentialModified();
        _audit.LogCredentialDeleted();

        var log = ReadLog();

        // The vault is encrypted; the plaintext log sitting next to it must not
        // reveal which services the user has an account with. The leak took the
        // form "Credential added: <title>".
        Assert.DoesNotContain("Credential added:", log);
        Assert.DoesNotContain("Credential modified:", log);
        Assert.DoesNotContain("Credential deleted:", log);
    }

    [Fact]
    public void LoggingStaysOffWhenDisabled()
    {
        AuditService.LoggingEnabled = false;

        _audit.LogCredentialAdded();

        Assert.Equal("", ReadLog());
    }
}
