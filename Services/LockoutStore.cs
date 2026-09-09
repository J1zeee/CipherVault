using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CipherVault.Services;

public sealed class LockoutState
{
    public int FailedAttempts { get; set; }
    public DateTime? LockoutStartUtc { get; set; }
}

/// <summary>
/// Persists brute-force lockout state next to the vault it guards, so the counter is
/// not reset by recreating <see cref="StorageService"/> or restarting the app.
///
/// The blob is sealed with DPAPI under the current Windows user: it cannot be edited
/// by hand and does not travel to another machine or account. It deliberately lives
/// in its own file so that exporting a vault (which ships only vault.dat) does not
/// carry an unreadable blob to the importing machine.
///
/// A missing or unreadable file is treated as "no failed attempts". That is fail-open
/// by design - failing closed would permanently lock a user out of their own vault
/// after any corruption, while an attacker who can delete this file already has the
/// encrypted vault and can attack it offline without going through the app at all.
/// </summary>
public sealed class LockoutStore
{
    private const string FileName = "lockout.dat";
    private static readonly byte[] Entropy = "CipherVault.Lockout.v1"u8.ToArray();

    private readonly string _path;

    public LockoutStore(string vaultFolder)
    {
        _path = Path.Combine(vaultFolder, FileName);
    }

    public LockoutState Load()
    {
        try
        {
            if (!File.Exists(_path))
                return new LockoutState();

            var protectedBytes = File.ReadAllBytes(_path);
            var plainBytes = ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.CurrentUser);
            var json = Encoding.UTF8.GetString(plainBytes);
            CryptographicOperations.ZeroMemory(plainBytes);

            return JsonSerializer.Deserialize<LockoutState>(json) ?? new LockoutState();
        }
        catch
        {
            return new LockoutState();
        }
    }

    public void Save(LockoutState state)
    {
        try
        {
            var plainBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(state));
            var protectedBytes = ProtectedData.Protect(plainBytes, Entropy, DataProtectionScope.CurrentUser);
            CryptographicOperations.ZeroMemory(plainBytes);

            AtomicFile.WriteAllBytes(_path, protectedBytes);
        }
        catch
        {
        }
    }

    public void Clear()
    {
        try
        {
            if (File.Exists(_path))
                File.Delete(_path);
            if (File.Exists(_path + AtomicFile.BackupSuffix))
                File.Delete(_path + AtomicFile.BackupSuffix);
        }
        catch
        {
        }
    }
}
