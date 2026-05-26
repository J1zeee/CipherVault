using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace CipherVault.Services;

public enum AuditEventType
{
    VaultCreated,
    VaultOpened,
    VaultClosed,
    LoginSuccess,
    LoginFailed,
    LoginLockedOut,
    VaultLocked,
    VaultUnlocked,
    CredentialAdded,
    CredentialModified,
    CredentialDeleted,
    PasswordGenerated,
    ClipboardCleared,
    SessionExpired,
    SecurityWarning
}

public sealed class AuditEntry
{
    public DateTime Timestamp { get; set; }
    public AuditEventType EventType { get; set; }
    public string Message { get; set; } = "";
    public string? AdditionalInfo { get; set; }
}

public sealed class AuditService : IDisposable
{
    private readonly string _auditPath;
    private readonly object _lockObj = new();
    private readonly int _maxLogSizeBytes;
    private bool _isDisposed;

    private const int DefaultMaxLogSizeBytes = 10 * 1024 * 1024;



    public static AuditService? Instance { get; private set; }

    public static AuditService Initialize(string? customPath = null, int maxLogSizeBytes = DefaultMaxLogSizeBytes)
    {
        if (Instance != null)
            return Instance;

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var folder = customPath ?? Path.Combine(appData, "CipherVault", "Logs");
        Directory.CreateDirectory(folder);

        Instance = new AuditService(folder, maxLogSizeBytes);
        return Instance;
    }

    public static AuditService GetInstance()
    {
        return Instance ?? throw new InvalidOperationException("AuditService not initialized");
    }

    private AuditService(string auditPath, int maxLogSizeBytes)
    {
        _auditPath = Path.Combine(auditPath, $"audit_{DateTime.UtcNow:yyyyMMdd}.log");
        _maxLogSizeBytes = maxLogSizeBytes;
    }

    public void LogEvent(AuditEventType eventType, string message, string? additionalInfo = null)
    {
        if (_isDisposed || !LoggingEnabled) return;

        var entry = new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            EventType = eventType,
            Message = message,
            AdditionalInfo = additionalInfo
        };

        WriteEntry(entry);
    }

    public void LogVaultCreated()
    {
        LogEvent(AuditEventType.VaultCreated, "New vault created successfully");
    }

    public void LogVaultOpened()
    {
        LogEvent(AuditEventType.VaultOpened, "Vault opened successfully");
    }

    public void LogVaultClosed()
    {
        LogEvent(AuditEventType.VaultClosed, "Vault closed");
    }

    public void LogLoginSuccess()
    {
        LogEvent(AuditEventType.LoginSuccess, "Successful login");
    }

    public void LogLoginFailed(int failedAttempts)
    {
        LogEvent(AuditEventType.LoginFailed,
            $"Failed login attempt #{failedAttempts}",
            $"Failed attempts: {failedAttempts}");
    }

    public void LogLoginLockedOut(int remainingSeconds)
    {
        LogEvent(AuditEventType.LoginLockedOut,
            $"Account locked due to too many failed attempts",
            $"Lockout duration: {remainingSeconds} seconds");
    }

    public void LogVaultLocked()
    {
        LogEvent(AuditEventType.VaultLocked, "Vault locked");
    }

    public void LogVaultUnlocked()
    {
        LogEvent(AuditEventType.VaultUnlocked, "Vault unlocked");
    }

    public void LogCredentialAdded(string title)
    {
        LogEvent(AuditEventType.CredentialAdded, $"Credential added: {title}");
    }

    public void LogCredentialModified(string title)
    {
        LogEvent(AuditEventType.CredentialModified, $"Credential modified: {title}");
    }

    public void LogCredentialDeleted(string title)
    {
        LogEvent(AuditEventType.CredentialDeleted, $"Credential deleted: {title}");
    }

    public void LogPasswordGenerated()
    {
        LogEvent(AuditEventType.PasswordGenerated, $"Password generated");
    }

    public void LogClipboardCleared()
    {
        LogEvent(AuditEventType.ClipboardCleared, "Clipboard auto-cleared");
    }

    public void LogSessionExpired()
    {
        LogEvent(AuditEventType.SessionExpired, "Session expired due to inactivity");
    }

    public void LogSecurityWarning(string warning)
    {
        LogEvent(AuditEventType.SecurityWarning, warning);
    }

    public List<string> GetRecentEntries(int count = 100)
    {
        var entries = new List<string>();

        if (!File.Exists(_auditPath))
            return entries;

        try
        {
            using var fs = new FileStream(_auditPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);

            var lines = new List<string>();
            while (!sr.EndOfStream)
            {
                var line = sr.ReadLine();
                if (!string.IsNullOrWhiteSpace(line))
                    lines.Add(line);
            }

            foreach (var line in lines.TakeLast(count))
            {
                entries.Add(line);
            }
        }
        catch { }

        return entries;
    }

    public void ExportLogs(string outputPath, DateTime? from = null, DateTime? to = null)
    {
        var logsFolder = Path.GetDirectoryName(_auditPath);
        if (logsFolder == null) return;

        var logFiles = Directory.GetFiles(logsFolder, "audit_*.log")
            .OrderBy(f => f)
            .ToList();

        using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
        using var writer = new StreamWriter(output);

        foreach (var logFile in logFiles)
        {
            try
            {
                using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);

                while (!sr.EndOfStream)
                {
                    var line = sr.ReadLine();
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    if (from.HasValue || to.HasValue)
                    {
                        if (TryParseTimestamp(line, out var timestamp))
                        {
                            if (from.HasValue && timestamp < from.Value)
                                continue;
                            if (to.HasValue && timestamp > to.Value)
                                continue;
                        }
                    }

                    writer.WriteLine(line);
                }
            }
            catch { }
        }
    }

    private bool TryParseTimestamp(string line, out DateTime timestamp)
    {
        timestamp = DateTime.MinValue;
        try
        {
            if (line.Length > 20 && line[0] == '[')
            {
                var endBracket = line.IndexOf(']');
                if (endBracket > 1)
                {
                    var dateStr = line.Substring(1, endBracket - 1);
                    if (DateTime.TryParseExact(dateStr, "yyyy.MM.dd HH:mm:ss", null,
                        System.Globalization.DateTimeStyles.None, out timestamp))
                    {
                        return true;
                    }
                }
            }
        }
        catch { }
        return false;
    }

    public void ClearOldLogs(int daysToKeep = 90)
    {
        var logsFolder = Path.GetDirectoryName(_auditPath);
        if (logsFolder == null) return;

        var cutoffDate = DateTime.UtcNow.AddDays(-daysToKeep);

        var logFiles = Directory.GetFiles(logsFolder, "audit_*.log");
        foreach (var file in logFiles)
        {
            try
            {
                var fileInfo = new FileInfo(file);
                if (fileInfo.CreationTimeUtc < cutoffDate)
                    File.Delete(file);
            }
            catch { }
        }
    }

    private void WriteEntry(AuditEntry entry)
    {
        lock (_lockObj)
        {
            try
            {
                CheckLogRotation();

                var timestamp = entry.Timestamp.ToString("yyyy.MM.dd HH:mm:ss");
                var eventName = entry.EventType.ToString();
                var logLine = $"[{timestamp}] {entry.Message} ({eventName})";

                if (!string.IsNullOrEmpty(entry.AdditionalInfo))
                {
                    logLine += $" | {entry.AdditionalInfo}";
                }

                using var fs = new FileStream(_auditPath, FileMode.Append, FileAccess.Write, FileShare.Read);
                using var sw = new StreamWriter(fs);
                sw.WriteLine(logLine);
            }
            catch
            {
            }
        }
    }

    private void CheckLogRotation()
    {
        if (!File.Exists(_auditPath))
            return;

        var fileInfo = new FileInfo(_auditPath);
        if (fileInfo.Length > _maxLogSizeBytes)
        {
            var archivePath = Path.Combine(
                Path.GetDirectoryName(_auditPath)!,
                $"audit_{DateTime.UtcNow:yyyyMMdd_HHmmss}_archived.log"
            );

            File.Move(_auditPath, archivePath);
        }
    }

    public void Dispose()
    {
        if (_isDisposed) return;

        lock (_lockObj)
        {
            if (_isDisposed) return;
            _isDisposed = true;
            Instance = null;
        }

        GC.SuppressFinalize(this);
    }

    public void ClearLogs()
    {
        try
        {
            var logsFolder = Path.GetDirectoryName(_auditPath);
            if (logsFolder != null && Directory.Exists(logsFolder))
            {
                foreach (var file in Directory.GetFiles(logsFolder, "audit_*.log"))
                {
                    File.Delete(file);
                }
            }
        }
        catch { }
    }

    private static bool _loggingEnabled = false;

    public static bool LoggingEnabled
    {
        get => _loggingEnabled;
        set => _loggingEnabled = value;
    }

    ~AuditService()
    {
        Dispose();
    }
}
