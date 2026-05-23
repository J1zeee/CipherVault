using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using CipherVault.Models;
using CipherVault.Services;

namespace CipherVault.ViewModels;

public class MainViewModel : INotifyPropertyChanged
{
    private readonly PasswordGenerator _passwordGenerator;
    private StorageService _storageService;
    
    private Credential? _selectedCredential;
    private string _searchQuery = "";
    private bool _isEditMode;
    private bool _isPasswordVisible;

    public MainViewModel(StorageService storageService)
    {
        _passwordGenerator = new PasswordGenerator();
        _storageService = storageService;
        
        Credentials = new ObservableCollection<Credential>();
        FilteredCredentials = new ObservableCollection<Credential>();
    }

    public void UpdateStorageService(StorageService storageService)
    {
        _storageService = storageService;
    }

    public ObservableCollection<Credential> Credentials { get; }
    public ObservableCollection<Credential> FilteredCredentials { get; }

    public Credential? SelectedCredential
    {
        get => _selectedCredential;
        set
        {
            _selectedCredential = value;
            OnPropertyChanged();
        }
    }

    public string SearchQuery
    {
        get => _searchQuery;
        set
        {
            _searchQuery = value;
            OnPropertyChanged();
            FilterCredentials();
        }
    }

    public bool IsEditMode
    {
        get => _isEditMode;
        set { _isEditMode = value; OnPropertyChanged(); }
    }

    public bool IsPasswordVisible
    {
        get => _isPasswordVisible;
        set { _isPasswordVisible = value; OnPropertyChanged(); }
    }

    public void StartAddCredential()
    {
        IsEditMode = false;
    }

    public void StartEditCredential()
    {
        IsEditMode = true;
    }

    public bool SaveCredential(Credential credential)
    {
        if (string.IsNullOrWhiteSpace(credential.Title))
            return false;

        try
        {
            if (IsEditMode && SelectedCredential != null)
            {
                var index = Credentials.IndexOf(SelectedCredential);
                if (index >= 0)
                {
                    var existing = Credentials.FirstOrDefault(c => 
                        c.Title.Equals(credential.Title, StringComparison.OrdinalIgnoreCase) && c != SelectedCredential);
                    if (existing != null) return false;

                    Credentials.RemoveAt(index);
                    credential.CreatedAt = SelectedCredential.CreatedAt;
                    credential.ModifiedAt = DateTime.Now;
                    Credentials.Insert(index, credential);
                }
            }
            else
            {
                var existing = Credentials.FirstOrDefault(c => 
                    c.Title.Equals(credential.Title, StringComparison.OrdinalIgnoreCase));
                if (existing != null) return false;

                credential.CreatedAt = DateTime.Now;
                credential.ModifiedAt = DateTime.Now;
                Credentials.Add(credential);
            }

            System.Diagnostics.Debug.WriteLine($"SaveCredential - Credentials count: {Credentials.Count}");
            _storageService.SaveVault(Credentials.ToList());
            System.Diagnostics.Debug.WriteLine("SaveCredential - SaveVault completed");
            
            SelectedCredential = credential;
            FilterCredentials();
            
            return true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"SaveCredential error: {ex.Message}");
            System.Diagnostics.Debug.WriteLine($"Stack trace: {ex.StackTrace}");
            return false;
        }
    }

    public void DeleteSelectedCredential()
    {
        if (SelectedCredential == null) return;

        // Securely clear the credential before removing
        SelectedCredential.SecureClear();
        
        Credentials.Remove(SelectedCredential);
        _storageService.SaveVault(Credentials.ToList());
        FilterCredentials();
        SelectedCredential = null;
    }

    public void TogglePasswordVisibility()
    {
        IsPasswordVisible = !IsPasswordVisible;
    }

    public void FilterCredentials()
    {
        FilteredCredentials.Clear();
        
        var filtered = string.IsNullOrWhiteSpace(SearchQuery)
            ? Credentials.ToList()
            : Credentials.Where(c =>
                (c.Title?.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (c.Username?.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (c.Email?.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (c.Website?.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ?? false)).ToList();

        foreach (var cred in filtered.OrderBy(c => c.Title))
        {
            FilteredCredentials.Add(cred);
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
