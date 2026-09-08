using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CipherVault.Models;

namespace CipherVault.Services;

public class StorageService : IDisposable
{
    private readonly string _dataPath;
    private readonly string _configPath;
    private SecureBuffer? _masterKey;
    private AuditService? _audit;
    private bool _isDisposed;
    private bool _isVaultOpen;

    private const int CurrentVersion = 1;
    private const int KeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;
    private const int SaltSizeBytes = 32;
    
    private const int MaxFailedAttempts = 5;
    private const int BaseDelaySeconds = 4;
    private const int MaxDelaySeconds = 2048;    
    
    private int _failedAttempts;
    private DateTime? _lockoutStartTime;
    private readonly LockoutStore _lockoutStore;

    public bool IsVaultOpen => _isVaultOpen;

    public StorageService(string? vaultPath = null)
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        
        var localFolder = vaultPath ?? Path.Combine(localAppData, "CipherVault");
        var roamingFolder = Path.Combine(roamingAppData, "CipherVault");
        
        Directory.CreateDirectory(localFolder);
        Directory.CreateDirectory(roamingFolder);
        
        _dataPath = Path.Combine(localFolder, "vault.dat");
        _configPath = Path.Combine(localFolder, "config.json");

        // Lockout state is persisted per vault: recreating this service (switching
        // vaults, restarting the app) must not hand an attacker a fresh attempt budget.
        _lockoutStore = new LockoutStore(localFolder);
        var lockoutState = _lockoutStore.Load();
        _failedAttempts = lockoutState.FailedAttempts;
        _lockoutStartTime = lockoutState.LockoutStartUtc;
        
        try
        {
            var logsPath = Path.Combine(roamingFolder, "Logs");
            _audit = AuditService.Initialize(logsPath);
        }
        catch
        {
        }
    }

    public bool VaultExists()
    {
        return File.Exists(_dataPath) && File.Exists(_configPath);
    }

    private VaultConfig? LoadConfig()
    {
        if (!File.Exists(_configPath)) return null;
        var json = File.ReadAllText(_configPath);
        return JsonSerializer.Deserialize<VaultConfig>(json);
    }

    private static byte[] UnlockAndCopy(SecureBuffer buffer)
    {
        buffer.BeginAccess();
        var copy = buffer.ToArray();
        buffer.EndAccess();
        return copy;
    }

    private static SecureBuffer DeriveKeyToBuffer(byte[] masterKeyRaw, byte[] info)
    {
        var key = new SecureBuffer(KeySizeBytes);
        var derivedBytes = HKDF.Expand(HashAlgorithmName.SHA256, masterKeyRaw, KeySizeBytes, info);
        key.Write(derivedBytes);
        CryptographicOperations.ZeroMemory(derivedBytes);
        key.EndAccess();
        return key;
    }

    private void ValidateVaultVersion(VaultConfig config)
    {
        if (config.Version < 1)
        {
            throw new InvalidOperationException("Invalid vault version");
        }

        if (config.Version > CurrentVersion)
        {
            throw new InvalidOperationException($"Vault version {config.Version} is not supported. Please update CipherVault.");
        }

        if (config.Version < CurrentVersion)
        {
            MigrateVault(config);
        }
    }

    private void MigrateVault(VaultConfig config)
    {
        while (config.Version < CurrentVersion)
        {
            switch (config.Version)
            {
                case 1:
                    throw new InvalidOperationException("Vault v1 is not supported in v2. Please delete vault data and create a new vault.");
                default:
                    throw new InvalidOperationException($"Migration from version {config.Version} not implemented");
            }
        }
    }

    /// <summary>
    /// Verifies the master password and, on success, opens the vault. The password
    /// buffer belongs to the caller and is neither retained nor wiped here.
    /// </summary>
    public (bool Success, string? ErrorMessage, int RemainingSeconds) VerifyPassword(ReadOnlySpan<byte> masterPassword)
    {
        // Record failed attempt even during lockout to increase future delays
        bool wasLockedOut = IsLockedOut(out int existingRemaining);
        
        if (wasLockedOut)
        {
            // Still record the failed attempt during lockout to extend future delays
            RecordFailedAttempt();
            _audit?.LogLoginLockedOut(existingRemaining);
            return (false, GetLockoutMessage(existingRemaining), existingRemaining);
        }

        var config = LoadConfig();
        if (config == null)
        {
            _audit?.LogSecurityWarning("Vault not found during login attempt");
            return (false, "Vault not found", 0);
        }

        ValidateVaultVersion(config);

        var salt = Convert.FromBase64String(config.Salt);
        var storedVerifyKey = Convert.FromBase64String(config.PasswordHash);
        
        SecureBuffer? masterKeyBuffer = null;
        byte[]? masterKeyRaw = null;
        SecureBuffer? computedVerifyKey = null;
        
        try
        {
            masterKeyBuffer = MasterKeyDerivation.Derive(masterPassword, salt);
            masterKeyRaw = UnlockAndCopy(masterKeyBuffer);
            computedVerifyKey = DeriveKeyToBuffer(masterKeyRaw, "verify"u8.ToArray());
            
            computedVerifyKey.BeginAccess();
            bool isValid = SecureMemory.FixedTimeEquals(computedVerifyKey.Span, storedVerifyKey.AsSpan());
            computedVerifyKey.EndAccess();
            
            if (isValid)
            {
                _masterKey?.Dispose();
                _masterKey = DeriveKeyToBuffer(masterKeyRaw, "encrypt"u8.ToArray());
                _isVaultOpen = true;
                
                ResetFailedAttempts();
                _audit?.LogLoginSuccess();
                _audit?.LogVaultOpened();
                return (true, null, 0);
            }
            else
            {
                int remaining = RecordFailedAttempt();
                _audit?.LogLoginFailed(_failedAttempts);
                
                if (remaining > 0)
                {
                    int delay = CalculateLockoutDelay();
                    _audit?.LogLoginLockedOut(delay);
                    return (false, GetLockoutMessage(delay), delay);
                }
                return (false, null, 0);
            }
        }
        finally
        {
            if (masterKeyRaw != null) CryptographicOperations.ZeroMemory(masterKeyRaw);
            masterKeyBuffer?.Dispose();
            computedVerifyKey?.Dispose();
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(storedVerifyKey);
        }
    }
    
    public bool IsLockedOut(out int remainingSeconds)
    {
        remainingSeconds = 0;
        
        if (_lockoutStartTime == null)
            return false;
        
        int delaySeconds = CalculateLockoutDelay();
        
        // Add 1 second to ensure we show full second before expiration
        var lockoutEnd = _lockoutStartTime.Value.AddSeconds(delaySeconds + 1);
        
        if (DateTime.UtcNow < lockoutEnd)
        {
            remainingSeconds = (int)(lockoutEnd - DateTime.UtcNow).TotalSeconds;
            return true;
        }
        
        return false;
    }
    
    public bool IsVaultLocked => IsLockedOut(out _);
    
    public int GetLockoutRemainingSeconds()
    {
        if (IsLockedOut(out int remaining))
            return remaining;
        return 0;
    }
    
    public int FailedAttempts => _failedAttempts;
    
    public int RemainingAttempts => Math.Max(0, MaxFailedAttempts - _failedAttempts);
    
    public void ResetLockout()
    {
        _failedAttempts = 0;
        _lockoutStartTime = null;
        _lockoutStore.Clear();
    }
    
    private int RecordFailedAttempt()
    {
        _failedAttempts++;
        
        if (_failedAttempts >= MaxFailedAttempts)
        {
            if (_lockoutStartTime == null)
            {
                _lockoutStartTime = DateTime.UtcNow;
            }
            else
            {
                // Extend lockout by recalculating delay - reset start time to now
                _lockoutStartTime = DateTime.UtcNow;
            }
        }
        
        PersistLockoutState();

        int delay = _failedAttempts >= MaxFailedAttempts ? CalculateLockoutDelay() : 0;
        return delay;
    }
    
    private void ResetFailedAttempts()
    {
        _failedAttempts = 0;
        _lockoutStartTime = null;
        _lockoutStore.Clear();
    }

    private void PersistLockoutState()
    {
        _lockoutStore.Save(new LockoutState
        {
            FailedAttempts = _failedAttempts,
            LockoutStartUtc = _lockoutStartTime
        });
    }
    
    private int CalculateLockoutDelay()
    {
        int excessAttempts = Math.Max(0, _failedAttempts - MaxFailedAttempts);
        int delay = (int)(BaseDelaySeconds * Math.Pow(2, excessAttempts));
        return Math.Min(delay, MaxDelaySeconds);
    }
    
    private string GetLockoutMessage(int delaySeconds)
    {
        // Return just the number - frontend will format with units
        return delaySeconds.ToString();
    }
    
    /// <summary>
    /// Creates a new vault. The password buffer belongs to the caller and is neither
    /// retained nor wiped here.
    /// </summary>
    public void CreateVault(ReadOnlySpan<byte> masterPassword)
    {
        var salt = new byte[SaltSizeBytes];
        RandomNumberGenerator.Fill(salt);
        
        SecureBuffer? masterKeyBuffer = null;
        byte[]? masterKeyRaw = null;
        SecureBuffer? verifyKeyBuffer = null;
        byte[]? verifyKeyBytes = null;
        
        try
        {
            masterKeyBuffer = MasterKeyDerivation.Derive(masterPassword, salt);
            masterKeyRaw = UnlockAndCopy(masterKeyBuffer);
            
            verifyKeyBuffer = DeriveKeyToBuffer(masterKeyRaw, "verify"u8.ToArray());
            verifyKeyBuffer.BeginAccess();
            verifyKeyBytes = verifyKeyBuffer.ToArray();
            verifyKeyBuffer.EndAccess();
            
            _masterKey = DeriveKeyToBuffer(masterKeyRaw, "encrypt"u8.ToArray());

            var config = new VaultConfig
            {
                Version = CurrentVersion,
                Salt = Convert.ToBase64String(salt),
                PasswordHash = Convert.ToBase64String(verifyKeyBytes)
            };

            var encrypted = Encrypt("[]"u8);

            AtomicFile.WriteAllBytes(_dataPath, encrypted);
            AtomicFile.WriteAllText(_configPath, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
            
            _audit?.LogVaultCreated();
            _isVaultOpen = true;
        }
        finally
        {
            if (masterKeyRaw != null) CryptographicOperations.ZeroMemory(masterKeyRaw);
            masterKeyBuffer?.Dispose();
            if (verifyKeyBytes != null) CryptographicOperations.ZeroMemory(verifyKeyBytes);
            verifyKeyBuffer?.Dispose();
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    public void LockVault()
    {
        if (_masterKey != null)
        {
            _masterKey.Dispose();
            _masterKey = null;
        }
        
        _audit?.LogVaultLocked();
        _isVaultOpen = false;
    }

    public void CloseVault()
    {
        ClearMasterKey();
        _audit?.LogVaultClosed();
        _isVaultOpen = false;
    }

    public List<Credential> LoadVault()
    {
        if (!File.Exists(_dataPath)) return new List<Credential>();

        var encrypted = File.ReadAllBytes(_dataPath);
        var plaintext = Decrypt(encrypted);

        try
        {
            var dtos = JsonSerializer.Deserialize<List<CredentialDto>>(plaintext)
                       ?? new List<CredentialDto>();

            var credentials = new List<Credential>();
            foreach (var dto in dtos)
            {
                var cred = new Credential();
                dto.ToCredential(cred);
                credentials.Add(cred);
            }

            return credentials;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public void SaveVault(List<Credential> credentials)
    {
        try
        {
            var dtos = credentials.Select(c => CredentialDto.FromCredential(c)).ToList();

            // Serialise straight to UTF-8 bytes we control. JsonSerializer.Serialize
            // produced a managed string holding every password in the vault at once,
            // which cannot be cleared once it exists.
            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
            {
                JsonSerializer.Serialize(writer, dtos);
            }

            var plaintext = buffer.GetBuffer();
            try
            {
                var encrypted = Encrypt(plaintext.AsSpan(0, (int)buffer.Length));
                AtomicFile.WriteAllBytes(_dataPath, encrypted);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"SaveVault error: {ex.Message}");
            throw;
        }
    }

    public void LogCredentialAdded()
    {
        _audit?.LogCredentialAdded();
    }

    public void LogCredentialModified()
    {
        _audit?.LogCredentialModified();
    }

    public void LogCredentialDeleted()
    {
        _audit?.LogCredentialDeleted();
    }

    public void LogPasswordGenerated()
    {
        _audit?.LogPasswordGenerated();
    }

    public void LogClipboardCleared()
    {
        _audit?.LogClipboardCleared();
    }

    public void LogSessionExpired()
    {
        _audit?.LogSessionExpired();
    }

    public List<string> GetAuditLog(int count = 100)
    {
        return _audit?.GetRecentEntries(count) ?? new List<string>();
    }

    public void ExportAuditLog(string path, DateTime? from = null, DateTime? to = null)
    {
        _audit?.ExportLogs(path, from, to);
    }

    private byte[] Encrypt(ReadOnlySpan<byte> plainBytes)
    {
        if (_masterKey == null) throw new InvalidOperationException("Not initialized");

        var nonce = new byte[NonceSizeBytes];
        RandomNumberGenerator.Fill(nonce);

        byte[]? cipherText = null;
        byte[]? tag = null;
        
        try
        {
            cipherText = new byte[plainBytes.Length];
            tag = new byte[TagSizeBytes];

            _masterKey.BeginAccess();
            
            using var aesGcm = new AesGcm(_masterKey.Span, TagSizeBytes);
            aesGcm.Encrypt(nonce, plainBytes, cipherText, tag);

            var result = new byte[NonceSizeBytes + cipherText.Length + TagSizeBytes];
            Buffer.BlockCopy(nonce, 0, result, 0, NonceSizeBytes);
            Buffer.BlockCopy(cipherText, 0, result, NonceSizeBytes, cipherText.Length);
            Buffer.BlockCopy(tag, 0, result, NonceSizeBytes + cipherText.Length, TagSizeBytes);

            return result;
        }
        finally
        {
            _masterKey?.EndAccess();
            CryptographicOperations.ZeroMemory(nonce);
            if (cipherText != null) CryptographicOperations.ZeroMemory(cipherText);
            if (tag != null) CryptographicOperations.ZeroMemory(tag);
        }
    }

    /// <summary>Returns the plaintext bytes; the caller is responsible for zeroing them.</summary>
    private byte[] Decrypt(byte[] cipherData)
    {
        if (_masterKey == null) throw new InvalidOperationException("Not initialized");

        if (cipherData.Length < NonceSizeBytes + TagSizeBytes)
            throw new InvalidOperationException("Invalid cipher data");

        var nonce = new byte[NonceSizeBytes];
        var tag = new byte[TagSizeBytes];
        var cipherText = new byte[cipherData.Length - NonceSizeBytes - TagSizeBytes];

        Buffer.BlockCopy(cipherData, 0, nonce, 0, NonceSizeBytes);
        Buffer.BlockCopy(cipherData, NonceSizeBytes, cipherText, 0, cipherText.Length);
        Buffer.BlockCopy(cipherData, NonceSizeBytes + cipherText.Length, tag, 0, TagSizeBytes);

        byte[]? plainBytes = null;
        
        try
        {
            plainBytes = new byte[cipherText.Length];

            _masterKey.BeginAccess();

            using var aesGcm = new AesGcm(_masterKey.Span, TagSizeBytes);
            aesGcm.Decrypt(nonce, cipherText, tag, plainBytes);

            return plainBytes;
        }
        catch (CryptographicException)
        {
            if (plainBytes != null) CryptographicOperations.ZeroMemory(plainBytes);
            throw new InvalidOperationException("Decryption failed - data may be tampered or corrupted");
        }
        finally
        {
            _masterKey?.EndAccess();
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(cipherText);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    public void ClearMasterKey()
    {
        _masterKey?.Dispose();
        _masterKey = null;
    }

    public void Dispose()
    {
        if (_isDisposed)
            return;

        CloseVault();
        _isDisposed = true;
        GC.SuppressFinalize(this);
    }

    // No finalizer: CloseVault writes to the audit log, and file I/O from the
    // finalizer thread during shutdown is a good way to hang or throw. The master
    // key's pinned memory is released by SecureBuffer's own finalizer.
}

public class VaultConfig
{
    public int Version { get; set; } = 1;
    public string Salt { get; set; } = "";
    public string PasswordHash { get; set; } = "";
}
