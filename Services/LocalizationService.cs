using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace CipherVault.Services;

public class LocalizationService : INotifyPropertyChanged
{
    private static LocalizationService? _instance;
    public static LocalizationService Instance => _instance ??= new LocalizationService();

    private string _currentLanguage = "en";
    
    private LocalizationService()
    {
        LoadLanguagePreference();
    }
    
    public event PropertyChangedEventHandler? PropertyChanged;
    public event Action? LanguageChanged;

    private readonly Dictionary<string, Dictionary<string, string>> _translations = new()
    {
        ["en"] = new Dictionary<string, string>
        {
            ["AppTitle"] = "CipherVault",
            ["AppSubtitle"] = "Password Manager",
            ["CreateMasterPassword"] = "Create Password",
            ["MasterPassword"] = "Password",
            ["ConfirmPassword"] = "Confirm Password",
            ["CreateVault"] = "Create Vault",
            ["WelcomeBack"] = "Welcome Back!",
            ["UnlockVault"] = "Unlock Vault",
            ["SearchCredentials"] = "Search credentials...",
            ["AddNew"] = "+ Add New",
            ["LockVault"] = "Lock Vault",
            ["SelectCredential"] = "Select a credential",
            ["SelectItemHint"] = "Choose an item from the list to view details",
            ["Username"] = "Username",
            ["Email"] = "Email",
            ["Password"] = "Password",
            ["Website"] = "Website",
            ["Notes"] = "Notes",
            ["NoNotes"] = "No notes",
            ["Created"] = "Created",
            ["Modified"] = "Modified",
            ["Title"] = "Title",
            ["TitleRequired"] = "Title *",
            ["AddNewCredential"] = "Add New Credential",
            ["EditCredential"] = "Edit Credential",
            ["Cancel"] = "Cancel",
            ["Save"] = "Save",
            ["PasswordGenerator"] = "Password Generator",
            ["Generate"] = "Generate",
            ["Regenerate"] = "Regenerate",
            ["Lowercase"] = "Lowercase (a-z)",
            ["Uppercase"] = "Uppercase (A-Z)",
            ["Numbers"] = "Numbers (0-9)",
            ["SpecialChars"] = "Special (!@#$...)",
            ["UsePassword"] = "Use Password",
            ["ClipboardCleared"] = "Clipboard cleared for security",
            ["SessionExpired"] = "Session expired due to inactivity",
            ["VeryWeak"] = "Very Weak",
            ["Weak"] = "Weak",
            ["Fair"] = "Fair",
            ["Good"] = "Good",
            ["Strong"] = "Very Strong",
            ["VeryStrong"] = "Very Strong",
            ["Entropy"] = "Entropy",
            ["CrackTime"] = "Crack time",
            ["Show"] = "Show",
            ["Hide"] = "Hide",
            ["Copy"] = "Copy",
            ["Edit"] = "Edit",
            ["Delete"] = "Delete",
            ["PasswordRequired"] = "Please enter a password",
            ["PasswordTooShort"] = "Password must be at least 8 characters",
            ["PasswordsMismatch"] = "Passwords do not match",
            ["EnterMasterPassword"] = "Please enter your password",
            ["IncorrectPassword"] = "Incorrect password",
            ["LockoutAttempts"] = "Too many failed login attempts. Please wait {0}",
            ["LockoutMessage"] = "Too many failed attempts. Try again in {0}",
            ["LockoutSeconds"] = "{0}s",
            ["LockoutMinutes"] = "{0}m",
            ["DecryptionFailed"] = "Failed to decrypt vault. Please delete vault data.",
            ["CredentialSaved"] = "Credential saved",
            ["CredentialDeleted"] = "'{0}' deleted",
            ["ConfirmDelete"] = "Confirm Delete",
            ["ConfirmDeleteMessage"] = "Delete '{0}'?",
            ["TitleRequiredError"] = "Title is required",
            ["ConfirmClearLogs"] = "Are you sure you want to clear all logs?",
            ["Confirm"] = "Confirm",
            ["LogsCleared"] = "Logs cleared successfully",
            ["UsernameCopied"] = "Username copied to clipboard",
            ["EmailCopied"] = "Email copied to clipboard",
            ["WebsiteCopied"] = "Website copied to clipboard",
            ["PasswordCopied"] = "Password copied to clipboard",
            ["CredentialsStored"] = "{0} credentials stored",
            ["Yes"] = "Yes",
            ["No"] = "No",
            ["Lang"] = "Language",
            ["VaultTampered"] = "The vault has been modified. Access denied.",
            ["Settings"] = "Settings",
            ["Interface"] = "Interface",
            ["FileLocation"] = "File Location",
            ["VaultPathDesc"] = "Vault storage path",
            ["Browse"] = "Browse",
            ["ResetDefault"] = "Reset to Default",
            ["LockVaultBeforePathChange"] = "Please lock the vault before changing storage paths.",
            ["VaultOpen"] = "Vault is Open",
            ["NoVaultAtPath"] = "No vault found at the specified path. Please create a new vault.",
            ["Warning"] = "Warning",
            ["Logging"] = "Logging",
            ["EnableLogging"] = "Enable logging",
            ["OpenLogsFolder"] = "Open Logs Folder",
            ["ClearLogs"] = "Clear Logs",
            ["LogsClearedSuccess"] = "Logs cleared successfully",
            ["ConfirmClearLogs"] = "Are you sure you want to clear all logs?",
            ["OK"] = "OK",
            ["Cancel"] = "Cancel",
            ["Confirm"] = "Confirm",
            ["ImportExport"] = "Import / Export",
            ["ExportVault"] = "Export Vault",
            ["Export"] = "Export",
            ["ImportVault"] = "Import Vault",
            ["ExportSuccess"] = "Vault exported successfully",
            ["ImportSuccess"] = "Vault imported successfully",
            ["SelectExportPath"] = "Select where to save the vault archive",
            ["SelectImportFile"] = "Select vault archive (.zip) or folder",
            ["ImportWarning"] = "This will replace your current vault. Continue?",
            ["InvalidImportSource"] = "Selected folder does not contain vault.dat and config.json",
            ["ExportFailed"] = "Failed to export vault",
            ["ImportFailed"] = "Failed to import vault",
            ["ZipFiles"] = "Zip Archives",
            ["AllFiles"] = "All Files",
            ["SelectVault"] = "Select Vault",
            ["CreateNewVault"] = "Create New Vault",
            ["VaultName"] = "Vault Name",
            ["VaultPath"] = "Vault Path",
            ["DeleteVault"] = "Delete",
            ["DeleteCurrentVault"] = "Delete Current Vault",
            ["DeleteVaultWarning"] = "This will permanently delete the vault files and all stored passwords. This cannot be undone.",
            ["VaultDeleted"] = "Vault deleted successfully",
            ["DeleteVaultConfirm"] = "Delete vault '{0}'? The vault files will remain on disk.",
            ["OpenVault"] = "Open",
            ["NoVaults"] = "No vaults yet. Create one to get started.",
            ["VaultCreated"] = "Vault created",
            ["VaultNameRequired"] = "Vault name is required",
            ["VaultNameExists"] = "A vault with this name already exists",
            ["LastOpened"] = "Last opened"
        },
        ["ru"] = new Dictionary<string, string>
        {
            ["AppTitle"] = "CipherVault",
            ["AppSubtitle"] = "Менеджер паролей",
            ["CreateMasterPassword"] = "Создать Пароль",
            ["MasterPassword"] = "Пароль",
            ["ConfirmPassword"] = "Подтвердите пароль",
            ["CreateVault"] = "Создать хранилище",
            ["WelcomeBack"] = "С возвращением!",
            ["UnlockVault"] = "Разблокировать",
            ["SearchCredentials"] = "Поиск учётных данных...",
            ["AddNew"] = "+ Добавить",
            ["LockVault"] = "Заблокировать",
            ["SelectCredential"] = "Выберите учётную запись",
            ["SelectItemHint"] = "Выберите элемент из списка для просмотра",
            ["Username"] = "Имя пользователя",
            ["Email"] = "Почта",
            ["Password"] = "Пароль",
            ["Website"] = "Веб-сайт",
            ["Notes"] = "Заметки",
            ["NoNotes"] = "Нет заметок",
            ["Created"] = "Создано",
            ["Modified"] = "Изменено",
            ["Title"] = "Название",
            ["TitleRequired"] = "Название *",
            ["AddNewCredential"] = "Новая учётная запись",
            ["EditCredential"] = "Редактировать",
            ["Cancel"] = "Отмена",
            ["Save"] = "Сохранить",
            ["PasswordGenerator"] = "Генератор паролей",
            ["Generate"] = "Сгенерировать",
            ["Regenerate"] = "Обновить",
            ["Lowercase"] = "Строчные (a-z)",
            ["Uppercase"] = "Заглавные (A-Z)",
            ["Numbers"] = "Цифры (0-9)",
            ["SpecialChars"] = "Спецсимволы (!@#$...)",
            ["UsePassword"] = "Использовать",
            ["ClipboardCleared"] = "Буфер обмена очищен для безопасности",
            ["SessionExpired"] = "Сессия истекла из-за бездействия",
            ["VeryWeak"] = "Очень слабый",
            ["Weak"] = "Слабый",
            ["Fair"] = "Средний",
            ["Good"] = "Хороший",
            ["Strong"] = "Надёжный",
            ["VeryStrong"] = "Очень надёжный",
            ["Entropy"] = "Энтропия",
            ["CrackTime"] = "Время взлома",
            ["Show"] = "Показать",
            ["Hide"] = "Скрыть",
            ["Copy"] = "Копировать",
            ["Edit"] = "Изменить",
            ["Delete"] = "Удалить",
            ["PasswordRequired"] = "Введите пароль",
            ["PasswordTooShort"] = "Пароль должен содержать минимум 8 символов",
            ["PasswordsMismatch"] = "Пароли не совпадают",
            ["EnterMasterPassword"] = "Введите пароль",
            ["IncorrectPassword"] = "Неверный пароль",
            ["LockoutAttempts"] = "Слишком много неверных попыток входа. Подождите {0}",
            ["LockoutMessage"] = "Слишком много попыток. Повторите через {0}",
            ["LockoutSeconds"] = "{0}с",
            ["LockoutMinutes"] = "{0}м",
            ["DecryptionFailed"] = "Не удалось расшифровать. Удалите данные хранилища.",
            ["CredentialSaved"] = "Учётная запись сохранена",
            ["CredentialDeleted"] = "'{0}' удалено",
            ["ConfirmDelete"] = "Подтвердить удаление",
            ["ConfirmDeleteMessage"] = "Удалить '{0}'?",
            ["TitleRequiredError"] = "Название обязательно",
            ["ConfirmClearLogs"] = "Вы уверены, что хотите очистить все логи?",
            ["Confirm"] = "Подтверждение",
            ["LogsCleared"] = "Логи успешно очищены",
            ["UsernameCopied"] = "Имя пользователя скопировано",
            ["EmailCopied"] = "Email скопирован",
            ["WebsiteCopied"] = "Веб-сайт скопирован",
            ["PasswordCopied"] = "Пароль скопирован",
            ["ClipboardCleared"] = "Буфер обмена очищен для безопасности",
            ["CredentialsStored"] = "{0} учётных записей сохранено",
            ["Yes"] = "Да",
            ["No"] = "Нет",
            ["Lang"] = "Язык",
            ["VaultTampered"] = "Хранилище было модифицировано. Вход невозможен.",
            ["Settings"] = "Настройки",
            ["Interface"] = "Интерфейс",
            ["FileLocation"] = "Расположение файлов",
            ["VaultPathDesc"] = "Путь к хранилищу",
            ["Browse"] = "Обзор",
            ["ResetDefault"] = "Сбросить",
            ["LockVaultBeforePathChange"] = "Заблокируйте хранилище перед изменением путей.",
            ["VaultOpen"] = "Хранилище открыто",
            ["NoVaultAtPath"] = "Хранилище не найдено по указанному пути. Создайте новое хранилище.",
            ["Warning"] = "Предупреждение",
            ["Logging"] = "Логирование",
            ["EnableLogging"] = "Включить логирование",
            ["OpenLogsFolder"] = "Открыть папку логов",
            ["ClearLogs"] = "Очистить логи",
            ["LogsClearedSuccess"] = "Логи успешно очищены",
            ["ConfirmClearLogs"] = "Вы уверены, что хотите очистить все логи?",
            ["OK"] = "ОК",
            ["Cancel"] = "Отмена",
            ["Confirm"] = "Подтвердить",
            ["ImportExport"] = "Импорт / Экспорт",
            ["ExportVault"] = "Экспорт хранилища",
            ["Export"] = "Экспорт",
            ["ImportVault"] = "Импорт хранилища",
            ["ExportSuccess"] = "Хранилище успешно экспортировано",
            ["ImportSuccess"] = "Хранилище успешно импортировано",
            ["SelectExportPath"] = "Выберите куда сохранить архив хранилища",
            ["SelectImportFile"] = "Выберите архив хранилища (.zip) или папку",
            ["ImportWarning"] = "Это заменит ваше текущее хранилище. Продолжить?",
            ["InvalidImportSource"] = "Выбранная папка не содержит vault.dat и config.json",
            ["ExportFailed"] = "Не удалось экспортировать хранилище",
            ["ImportFailed"] = "Не удалось импортировать хранилище",
            ["ZipFiles"] = "Zip архивы",
            ["AllFiles"] = "Все файлы",
            ["SelectVault"] = "Выберите хранилище",
            ["CreateNewVault"] = "Создать хранилище",
            ["VaultName"] = "Название хранилища",
            ["VaultPath"] = "Путь к хранилищу",
            ["DeleteVault"] = "Удалить",
            ["DeleteCurrentVault"] = "Удалить текущее хранилище",
            ["DeleteVaultWarning"] = "Это навсегда удалит файлы хранилища и все сохранённые пароли. Это действие нельзя отменить.",
            ["VaultDeleted"] = "Хранилище успешно удалено",
            ["DeleteVaultConfirm"] = "Удалить хранилище '{0}'? Файлы хранилища останутся на диске.",
            ["OpenVault"] = "Открыть",
            ["NoVaults"] = "Хранилищ пока нет. Создайте новое, чтобы начать.",
            ["VaultCreated"] = "Хранилище создано",
            ["VaultNameRequired"] = "Название хранилища обязательно",
            ["VaultNameExists"] = "Хранилище с таким именем уже существует",
            ["LastOpened"] = "Последнее открытие"
        }
    };

    public string CurrentLanguage
    {
        get => _currentLanguage;
        set
        {
            if (_currentLanguage != value && _translations.ContainsKey(value))
            {
                _currentLanguage = value;
                SaveLanguagePreference();
                OnPropertyChanged();
                LanguageChanged?.Invoke();
            }
        }
    }

    public string this[string key] => Get(key);

    public string Get(string key)
    {
        if (_translations.TryGetValue(_currentLanguage, out var lang) && lang.TryGetValue(key, out var value))
            return value;
        if (_translations["en"].TryGetValue(key, out var fallback))
            return fallback;
        return key;
    }

    public string GetFormatted(string key, params object[] args)
    {
        return string.Format(Get(key), args);
    }

    public void LoadLanguagePreference()
    {
        try
        {
            var configPath = Path.Combine(GetConfigDirectory(), "settings.json");
            if (File.Exists(configPath))
            {
                var json = File.ReadAllText(configPath);
                var config = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                if (config != null && config.TryGetValue("language", out var lang) && _translations.ContainsKey(lang))
                {
                    _currentLanguage = lang;
                }
            }
        }
        catch { }
    }

    private void SaveLanguagePreference()
    {
        try
        {
            var configPath = Path.Combine(GetConfigDirectory(), "settings.json");
            Dictionary<string, string> config;
            
            if (File.Exists(configPath))
            {
                var json = File.ReadAllText(configPath);
                config = JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? new();
            }
            else
            {
                config = new();
            }
            
            config["language"] = _currentLanguage;
            File.WriteAllText(configPath, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }

    private static string GetConfigDirectory()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var dir = Path.Combine(appData, "CipherVault");
        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);
        return dir;
    }

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
