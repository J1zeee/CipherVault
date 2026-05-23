using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using CipherVault.Services;

namespace CipherVault.Models;

public class Credential : INotifyPropertyChanged, IDisposable
{
    private SecureBuffer? _titleBuffer;
    private SecureBuffer? _usernameBuffer;
    private SecureBuffer? _emailBuffer;
    private SecureBuffer? _passwordBuffer;
    private SecureBuffer? _websiteBuffer;
    private SecureBuffer? _notesBuffer;
    private bool _isDisposed;
    private static readonly object _lockObj = new();

    [JsonIgnore]
    public string Title
    {
        get => GetSecureString(nameof(Title));
        set => SetSecureString(nameof(Title), value);
    }

    [JsonIgnore]
    public string Username
    {
        get => GetSecureString(nameof(Username));
        set => SetSecureString(nameof(Username), value);
    }

    [JsonIgnore]
    public string Email
    {
        get => GetSecureString(nameof(Email));
        set => SetSecureString(nameof(Email), value);
    }

    [JsonIgnore]
    public string Password
    {
        get => GetSecureString(nameof(Password));
        set => SetSecureString(nameof(Password), value);
    }

    [JsonIgnore]
    public string Website
    {
        get => GetSecureString(nameof(Website));
        set => SetSecureString(nameof(Website), value);
    }

    [JsonIgnore]
    public string Notes
    {
        get => GetSecureString(nameof(Notes));
        set => SetSecureString(nameof(Notes), value);
    }

    [JsonPropertyName("title")]
    public string? TitleJson
    {
        get => GetSecureString(nameof(Title));
        set => SetSecureString(nameof(Title), value ?? "");
    }

    [JsonPropertyName("username")]
    public string? UsernameJson
    {
        get => GetSecureString(nameof(Username));
        set => SetSecureString(nameof(Username), value ?? "");
    }

    [JsonPropertyName("email")]
    public string? EmailJson
    {
        get => GetSecureString(nameof(Email));
        set => SetSecureString(nameof(Email), value ?? "");
    }

    [JsonPropertyName("password")]
    public string? PasswordJson
    {
        get => GetSecureString(nameof(Password));
        set => SetSecureString(nameof(Password), value ?? "");
    }

    [JsonPropertyName("website")]
    public string? WebsiteJson
    {
        get => GetSecureString(nameof(Website));
        set => SetSecureString(nameof(Website), value ?? "");
    }

    [JsonPropertyName("notes")]
    public string? NotesJson
    {
        get => GetSecureString(nameof(Notes));
        set => SetSecureString(nameof(Notes), value ?? "");
    }

    [JsonPropertyName("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.Now;

    [JsonPropertyName("modifiedAt")]
    public DateTime ModifiedAt { get; set; } = DateTime.Now;

    private string GetSecureString(string fieldName)
    {
        lock (_lockObj)
        {
            var buffer = GetSecureBuffer(fieldName);
            if (buffer != null)
            {
                try
                {
                    buffer.UnprotectAndUnlock();
                    var span = buffer.Span;
                    var result = System.Text.Encoding.UTF8.GetString(span);
                    result = result.TrimEnd('\0');
                    buffer.CommitAndProtect();
                    
                    // Return space if empty to allow Title[0] binding to work
                    return string.IsNullOrEmpty(result) ? " " : result;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"GetSecureString error for {fieldName}: {ex.Message}");
                    return " ";
                }
            }
            return " ";
        }
    }

    private void SetSecureString(string fieldName, string value)
    {
        lock (_lockObj)
        {
            ClearSecureBuffer(fieldName);

            if (string.IsNullOrEmpty(value))
            {
                OnPropertyChanged(fieldName);
                return;
            }

            try
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(value);
                var paddedLength = ((bytes.Length + 15) / 16) * 16;
                var buffer = SecureMemory.Allocate(paddedLength);
                buffer.Write(bytes);
                buffer.CommitAndProtect();

                CryptographicOperations.ZeroMemory(bytes);
                Array.Clear(bytes, 0, bytes.Length);

                switch (fieldName)
                {
                    case nameof(Title):
                        _titleBuffer = buffer;
                        break;
                    case nameof(Username):
                        _usernameBuffer = buffer;
                        break;
                    case nameof(Email):
                        _emailBuffer = buffer;
                        break;
                    case nameof(Password):
                        _passwordBuffer = buffer;
                        break;
                    case nameof(Website):
                        _websiteBuffer = buffer;
                        break;
                    case nameof(Notes):
                        _notesBuffer = buffer;
                        break;
                }

                OnPropertyChanged(fieldName);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"SetSecureString error for {fieldName}: {ex.Message}");
            }
        }
    }

    private SecureBuffer? GetSecureBuffer(string fieldName)
    {
        return fieldName switch
        {
            nameof(Title) => _titleBuffer,
            nameof(Username) => _usernameBuffer,
            nameof(Email) => _emailBuffer,
            nameof(Password) => _passwordBuffer,
            nameof(Website) => _websiteBuffer,
            nameof(Notes) => _notesBuffer,
            _ => null
        };
    }

    private void ClearSecureBuffer(string fieldName)
    {
        switch (fieldName)
        {
            case nameof(Title):
                _titleBuffer?.Dispose();
                _titleBuffer = null;
                break;
            case nameof(Username):
                _usernameBuffer?.Dispose();
                _usernameBuffer = null;
                break;
            case nameof(Email):
                _emailBuffer?.Dispose();
                _emailBuffer = null;
                break;
            case nameof(Password):
                _passwordBuffer?.Dispose();
                _passwordBuffer = null;
                break;
            case nameof(Website):
                _websiteBuffer?.Dispose();
                _websiteBuffer = null;
                break;
            case nameof(Notes):
                _notesBuffer?.Dispose();
                _notesBuffer = null;
                break;
        }
    }

    public void SecureClear()
    {
        lock (_lockObj)
        {
            _titleBuffer?.Dispose();
            _usernameBuffer?.Dispose();
            _emailBuffer?.Dispose();
            _passwordBuffer?.Dispose();
            _websiteBuffer?.Dispose();
            _notesBuffer?.Dispose();

            _titleBuffer = null;
            _usernameBuffer = null;
            _emailBuffer = null;
            _passwordBuffer = null;
            _websiteBuffer = null;
            _notesBuffer = null;

            OnPropertyChanged(nameof(Title));
            OnPropertyChanged(nameof(Username));
            OnPropertyChanged(nameof(Email));
            OnPropertyChanged(nameof(Password));
            OnPropertyChanged(nameof(Website));
            OnPropertyChanged(nameof(Notes));
        }
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        SecureClear();
        _isDisposed = true;
        GC.SuppressFinalize(this);
    }

    ~Credential()
    {
        Dispose();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

public class CredentialDto
{
    [JsonPropertyName("title")]
    public string Title { get; set; } = "";

    [JsonPropertyName("username")]
    public string Username { get; set; } = "";

    [JsonPropertyName("email")]
    public string Email { get; set; } = "";

    [JsonPropertyName("password")]
    public string Password { get; set; } = "";

    [JsonPropertyName("website")]
    public string Website { get; set; } = "";

    [JsonPropertyName("notes")]
    public string Notes { get; set; } = "";

    [JsonPropertyName("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.Now;

    [JsonPropertyName("modifiedAt")]
    public DateTime ModifiedAt { get; set; } = DateTime.Now;

    public static CredentialDto FromCredential(Credential cred)
    {
        return new CredentialDto
        {
            Title = cred.Title,
            Username = cred.Username,
            Email = cred.Email,
            Password = cred.Password,
            Website = cred.Website,
            Notes = cred.Notes,
            CreatedAt = cred.CreatedAt,
            ModifiedAt = cred.ModifiedAt
        };
    }

    public void ToCredential(Credential cred)
    {
        cred.Title = Title;
        cred.Username = Username;
        cred.Email = Email;
        cred.Password = Password;
        cred.Website = Website;
        cred.Notes = Notes;
        cred.CreatedAt = CreatedAt;
        cred.ModifiedAt = ModifiedAt;
    }
}