using System.IO;
using System.Text.Json;

namespace CipherVault.Services;

/// <summary>
/// Typed access to settings.json. Every write is a read-modify-write of the whole
/// document, so components that own different keys - the vault path here, the UI
/// language in <see cref="LocalizationService"/> - do not drop each other's values.
/// Unreadable settings fall back to defaults rather than throwing: a corrupt
/// preferences file must not stop the app from starting.
/// </summary>
public sealed class AppSettingsStore
{
    public const string VaultPathKey = "vaultPath";
    public const string LoggingEnabledKey = "loggingEnabled";
    public const string ScreenCaptureProtectionKey = "screenCaptureProtection";

    private readonly string _path;

    public AppSettingsStore(string configDirectory)
    {
        Directory.CreateDirectory(configDirectory);
        _path = Path.Combine(configDirectory, "settings.json");
    }

    public string? GetString(string key)
    {
        return Read().TryGetValue(key, out var value) && !string.IsNullOrEmpty(value)
            ? value
            : null;
    }

    public void SetString(string key, string value)
    {
        var settings = Read();
        settings[key] = value;
        Write(settings);
    }

    public bool GetBool(string key, bool defaultValue = false)
    {
        var raw = GetString(key);
        return raw != null && bool.TryParse(raw, out var parsed) ? parsed : defaultValue;
    }

    public void SetBool(string key, bool value)
    {
        SetString(key, value ? "true" : "false");
    }

    private Dictionary<string, string> Read()
    {
        try
        {
            if (!File.Exists(_path))
                return new Dictionary<string, string>();

            var json = File.ReadAllText(_path);
            return JsonSerializer.Deserialize<Dictionary<string, string>>(json)
                   ?? new Dictionary<string, string>();
        }
        catch
        {
            return new Dictionary<string, string>();
        }
    }

    private void Write(Dictionary<string, string> settings)
    {
        try
        {
            var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
            AtomicFile.WriteAllText(_path, json);
        }
        catch
        {
        }
    }
}
