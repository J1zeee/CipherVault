using System.IO;
using System.Text;
using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class LockoutStoreTests : IDisposable
{
    private readonly string _dir;

    public LockoutStoreTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "CipherVaultTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    [Fact]
    public void Load_ReturnsZeroAttemptsWhenNothingPersisted()
    {
        var state = new LockoutStore(_dir).Load();

        Assert.Equal(0, state.FailedAttempts);
        Assert.Null(state.LockoutStartUtc);
    }

    [Fact]
    public void Save_ThenLoad_RoundTripsFailedAttempts()
    {
        var start = new DateTime(2026, 3, 14, 12, 0, 0, DateTimeKind.Utc);
        new LockoutStore(_dir).Save(new LockoutState { FailedAttempts = 7, LockoutStartUtc = start });

        var state = new LockoutStore(_dir).Load();

        Assert.Equal(7, state.FailedAttempts);
        Assert.Equal(start, state.LockoutStartUtc);
    }

    [Fact]
    public void Save_DoesNotWriteAttemptCountInReadableForm()
    {
        new LockoutStore(_dir).Save(new LockoutState { FailedAttempts = 7, LockoutStartUtc = DateTime.UtcNow });

        var raw = File.ReadAllBytes(Path.Combine(_dir, "lockout.dat"));
        var asText = Encoding.UTF8.GetString(raw);

        Assert.DoesNotContain("FailedAttempts", asText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("LockoutStartUtc", asText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Load_ReturnsZeroAttemptsWhenFileIsCorrupt()
    {
        File.WriteAllText(Path.Combine(_dir, "lockout.dat"), "not a DPAPI blob");

        var state = new LockoutStore(_dir).Load();

        Assert.Equal(0, state.FailedAttempts);
        Assert.Null(state.LockoutStartUtc);
    }

    [Fact]
    public void Clear_RemovesPersistedState()
    {
        var store = new LockoutStore(_dir);
        store.Save(new LockoutState { FailedAttempts = 3, LockoutStartUtc = DateTime.UtcNow });

        store.Clear();

        Assert.Equal(0, store.Load().FailedAttempts);
    }
}
