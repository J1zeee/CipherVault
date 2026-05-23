using System.IO;
using System.Text.Json;

namespace CipherVault.Services;

public class VaultInfo
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public DateTime Created { get; set; }
    public DateTime LastOpened { get; set; }
}

public class VaultManagerService
{
    private static VaultManagerService? _instance;
    public static VaultManagerService Instance => _instance ??= new VaultManagerService();

    private readonly string _vaultsFilePath;
    private List<VaultInfo> _vaults = new();

    private VaultManagerService()
    {
        var configDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CipherVault");
        Directory.CreateDirectory(configDir);
        _vaultsFilePath = Path.Combine(configDir, "vaults.json");
        LoadVaults();
    }

    public List<VaultInfo> GetAllVaults() => _vaults;

    public VaultInfo? GetVaultById(string id) => _vaults.FirstOrDefault(v => v.Id == id);

    public VaultInfo CreateVault(string name, string path)
    {
        var vault = new VaultInfo
        {
            Id = Guid.NewGuid().ToString("N"),
            Name = name,
            Path = path,
            Created = DateTime.Now,
            LastOpened = DateTime.Now
        };

        Directory.CreateDirectory(path);
        _vaults.Add(vault);
        SaveVaults();
        return vault;
    }

    public void DeleteVault(string id)
    {
        var vault = _vaults.FirstOrDefault(v => v.Id == id);
        if (vault != null)
        {
            _vaults.Remove(vault);
            SaveVaults();
        }
    }

    public void UpdateLastOpened(string id)
    {
        var vault = _vaults.FirstOrDefault(v => v.Id == id);
        if (vault != null)
        {
            vault.LastOpened = DateTime.Now;
            SaveVaults();
        }
    }

    private void LoadVaults()
    {
        try
        {
            if (File.Exists(_vaultsFilePath))
            {
                var json = File.ReadAllText(_vaultsFilePath);
                _vaults = JsonSerializer.Deserialize<List<VaultInfo>>(json) ?? new();
            }
        }
        catch { }
    }

    private void SaveVaults()
    {
        try
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(_vaultsFilePath, JsonSerializer.Serialize(_vaults, options));
        }
        catch { }
    }
}
