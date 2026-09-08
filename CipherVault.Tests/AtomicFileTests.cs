using System.IO;
using System.Text;
using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class AtomicFileTests : IDisposable
{
    private readonly string _dir;
    private readonly string _path;

    public AtomicFileTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "CipherVaultTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "vault.dat");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    [Fact]
    public void CreatesFileWhenNoneExists()
    {
        AtomicFile.WriteAllBytes(_path, Encoding.UTF8.GetBytes("first"));

        Assert.Equal("first", File.ReadAllText(_path));
    }

    [Fact]
    public void ReplacesExistingContentCompletely()
    {
        AtomicFile.WriteAllBytes(_path, Encoding.UTF8.GetBytes("a much longer original payload"));
        AtomicFile.WriteAllBytes(_path, Encoding.UTF8.GetBytes("short"));

        Assert.Equal("short", File.ReadAllText(_path));
    }

    [Fact]
    public void KeepsPreviousContentAsBackup()
    {
        AtomicFile.WriteAllBytes(_path, Encoding.UTF8.GetBytes("original"));
        AtomicFile.WriteAllBytes(_path, Encoding.UTF8.GetBytes("updated"));

        Assert.Equal("original", File.ReadAllText(_path + ".bak"));
    }

    [Fact]
    public void LeavesNoTempFileBehind()
    {
        AtomicFile.WriteAllBytes(_path, Encoding.UTF8.GetBytes("payload"));

        Assert.False(File.Exists(_path + ".tmp"));
    }

    [Fact]
    public void SucceedsWhenStaleTempFileFromEarlierCrashExists()
    {
        File.WriteAllText(_path + ".tmp", "garbage left by a crashed write");

        AtomicFile.WriteAllBytes(_path, Encoding.UTF8.GetBytes("payload"));

        Assert.Equal("payload", File.ReadAllText(_path));
        Assert.False(File.Exists(_path + ".tmp"));
    }

    [Fact]
    public void WriteAllTextRoundTripsUtf8()
    {
        AtomicFile.WriteAllText(_path, "привет {\"a\":1}");

        Assert.Equal("привет {\"a\":1}", File.ReadAllText(_path));
    }
}
