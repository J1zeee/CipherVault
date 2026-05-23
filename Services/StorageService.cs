using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CipherVault.Models;
using Konscious.Security.Cryptography;

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
    private const int Argon2Iterations = 3;
    private const int Argon2MemoryKB = 131072;
    private const int Argon2Parallelism = 4;
    private const int KeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;
    private const int SaltSizeBytes = 32;
    
    private const int MaxFailedAttempts = 5;
    private const int BaseDelaySeconds = 4;
    private const int MaxDelaySeconds = 2048;    
    
    private int _failedAttempts;
    private DateTime? _lockoutStartTime;

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

    private static SecureBuffer DeriveMasterKeyRaw(ReadOnlySpan<byte> passwordBytes, ReadOnlySpan<byte> salt)
    {
        var key = new SecureBuffer(KeySizeBytes);
        var derivedBytes = new Argon2id(passwordBytes.ToArray())
        {
            Salt = salt.ToArray(),
            DegreeOfParallelism = Argon2Parallelism,
            MemorySize = Argon2MemoryKB,
            Iterations = Argon2Iterations
        }.GetBytes(KeySizeBytes);
        key.Write(derivedBytes);
        CryptographicOperations.ZeroMemory(derivedBytes);
        key.CommitAndProtect();
        return key;
    }

    private static byte[] UnlockAndCopy(SecureBuffer buffer)
    {
        buffer.UnprotectAndUnlock();
        var copy = buffer.ToArray();
        buffer.CommitAndProtect();
        return copy;
    }

    private static SecureBuffer DeriveKeyToBuffer(byte[] masterKeyRaw, byte[] info)
    {
        var key = new SecureBuffer(KeySizeBytes);
        var derivedBytes = HKDF.Expand(HashAlgorithmName.SHA256, masterKeyRaw, KeySizeBytes, info);
        key.Write(derivedBytes);
        CryptographicOperations.ZeroMemory(derivedBytes);
        key.CommitAndProtect();
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

    public (bool Success, string? ErrorMessage, int RemainingSeconds) VerifyPassword(string masterPassword)
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

        var salt = Convert.FromBase64String(config.Salt);
        var storedVerifyKey = Convert.FromBase64String(config.PasswordHash);
        
        byte[]? passwordBytes = null;
        SecureBuffer? masterKeyBuffer = null;
        byte[]? masterKeyRaw = null;
        SecureBuffer? computedVerifyKey = null;
        
        try
        {
            passwordBytes = Encoding.UTF8.GetBytes(masterPassword);
            masterKeyBuffer = DeriveMasterKeyRaw(passwordBytes, salt);
            masterKeyRaw = UnlockAndCopy(masterKeyBuffer);
            computedVerifyKey = DeriveKeyToBuffer(masterKeyRaw, "verify"u8.ToArray());
            
            computedVerifyKey.UnprotectAndUnlock();
            bool isValid = SecureMemory.FixedTimeEquals(computedVerifyKey.Span, storedVerifyKey.AsSpan());
            computedVerifyKey.CommitAndProtect();
            
            if (isValid)
            {
                _masterKey = DeriveKeyToBuffer(masterKeyRaw, "encrypt"u8.ToArray());
                
                ResetFailedAttempts();
                _audit?.LogLoginSuccess();
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
            if (passwordBytes != null) CryptographicOperations.ZeroMemory(passwordBytes);
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
        
        int delay = _failedAttempts >= MaxFailedAttempts ? CalculateLockoutDelay() : 0;
        return delay;
    }
    
    private void ResetFailedAttempts()
    {
        _failedAttempts = 0;
        _lockoutStartTime = null;
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
    
    public void CreateVault(string masterPassword)
    {
        var salt = new byte[SaltSizeBytes];
        RandomNumberGenerator.Fill(salt);
        
        byte[]? passwordBytes = null;
        SecureBuffer? masterKeyBuffer = null;
        byte[]? masterKeyRaw = null;
        SecureBuffer? verifyKeyBuffer = null;
        byte[]? verifyKeyBytes = null;
        
        try
        {
            passwordBytes = Encoding.UTF8.GetBytes(masterPassword);
            masterKeyBuffer = DeriveMasterKeyRaw(passwordBytes, salt);
            masterKeyRaw = UnlockAndCopy(masterKeyBuffer);
            
            verifyKeyBuffer = DeriveKeyToBuffer(masterKeyRaw, "verify"u8.ToArray());
            verifyKeyBuffer.UnprotectAndUnlock();
            verifyKeyBytes = verifyKeyBuffer.ToArray();
            verifyKeyBuffer.CommitAndProtect();
            
            _masterKey = DeriveKeyToBuffer(masterKeyRaw, "encrypt"u8.ToArray());

            var config = new VaultConfig
            {
                Version = CurrentVersion,
                Salt = Convert.ToBase64String(salt),
                PasswordHash = Convert.ToBase64String(verifyKeyBytes)
            };

            var json = JsonSerializer.Serialize(new List<Credential>());
            var encrypted = Encrypt(json);

            File.WriteAllBytes(_dataPath, encrypted);
            File.WriteAllText(_configPath, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
            
            _audit?.LogVaultCreated();
            _isVaultOpen = true;
        }
        finally
        {
            if (passwordBytes != null) CryptographicOperations.ZeroMemory(passwordBytes);
            if (masterKeyRaw != null) CryptographicOperations.ZeroMemory(masterKeyRaw);
            masterKeyBuffer?.Dispose();
            if (verifyKeyBytes != null) CryptographicOperations.ZeroMemory(verifyKeyBytes);
            verifyKeyBuffer?.Dispose();
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    public void Initialize(string masterPassword)
    {
        var config = LoadConfig();
        if (config == null) return;

        ValidateVaultVersion(config);

        var salt = Convert.FromBase64String(config.Salt);
        byte[]? passwordBytes = null;
        SecureBuffer? masterKeyBuffer = null;
        byte[]? masterKeyRaw = null;
        
        try
        {
            passwordBytes = Encoding.UTF8.GetBytes(masterPassword);
            masterKeyBuffer = DeriveMasterKeyRaw(passwordBytes, salt);
            masterKeyRaw = UnlockAndCopy(masterKeyBuffer);
            
            _masterKey?.Dispose();
            _masterKey = DeriveKeyToBuffer(masterKeyRaw, "encrypt"u8.ToArray());
            
            _audit?.LogVaultOpened();
            _isVaultOpen = true;
        }
        finally
        {
            if (passwordBytes != null) CryptographicOperations.ZeroMemory(passwordBytes);
            if (masterKeyRaw != null) CryptographicOperations.ZeroMemory(masterKeyRaw);
            masterKeyBuffer?.Dispose();
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
        var json = Decrypt(encrypted);
        
        var dtos = JsonSerializer.Deserialize<List<CredentialDto>>(json) ?? new List<CredentialDto>();
        
        var credentials = new List<Credential>();
        foreach (var dto in dtos)
        {
            var cred = new Credential();
            dto.ToCredential(cred);
            credentials.Add(cred);
        }
        
        return credentials;
    }

    public void SaveVault(List<Credential> credentials)
    {
        try
        {
            var dtos = credentials.Select(c => CredentialDto.FromCredential(c)).ToList();
            var json = JsonSerializer.Serialize(dtos, new JsonSerializerOptions { WriteIndented = true });
            var encrypted = Encrypt(json);
            File.WriteAllBytes(_dataPath, encrypted);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"SaveVault error: {ex.Message}");
            throw;
        }
    }

    public void LogCredentialAdded(string title)
    {
        _audit?.LogCredentialAdded(title);
    }

    public void LogCredentialModified(string title)
    {
        _audit?.LogCredentialModified(title);
    }

    public void LogCredentialDeleted(string title)
    {
        _audit?.LogCredentialDeleted(title);
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

    private byte[] Encrypt(string plainText)
    {
        if (_masterKey == null) throw new InvalidOperationException("Not initialized");

        var nonce = new byte[NonceSizeBytes];
        RandomNumberGenerator.Fill(nonce);

        byte[]? plainBytes = null;
        byte[]? cipherText = null;
        byte[]? tag = null;
        
        try
        {
            plainBytes = Encoding.UTF8.GetBytes(plainText);
            cipherText = new byte[plainBytes.Length];
            tag = new byte[TagSizeBytes];

            _masterKey.UnprotectAndUnlock();
            
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
            _masterKey?.CommitAndProtect();
            CryptographicOperations.ZeroMemory(nonce);
            if (plainBytes != null) CryptographicOperations.ZeroMemory(plainBytes);
            if (cipherText != null) CryptographicOperations.ZeroMemory(cipherText);
            if (tag != null) CryptographicOperations.ZeroMemory(tag);
        }
    }

    private string Decrypt(byte[] cipherData)
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

            _masterKey.UnprotectAndUnlock();

            using var aesGcm = new AesGcm(_masterKey.Span, TagSizeBytes);
            aesGcm.Decrypt(nonce, cipherText, tag, plainBytes);

            var result = Encoding.UTF8.GetString(plainBytes);
            return result;
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException("Decryption failed - data may be tampered or corrupted");
        }
        finally
        {
            _masterKey?.CommitAndProtect();
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(cipherText);
            CryptographicOperations.ZeroMemory(tag);
            if (plainBytes != null) CryptographicOperations.ZeroMemory(plainBytes);
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

    ~StorageService()
    {
        Dispose();
    }
}

public class VaultConfig
{
    public int Version { get; set; } = 1;
    public string Salt { get; set; } = "";
    public string PasswordHash { get; set; } = "";
}
