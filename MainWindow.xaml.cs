using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Threading;
using CipherVault.Models;
using CipherVault.Services;
using CipherVault.ViewModels;
using Microsoft.Win32;

namespace CipherVault;

public partial class MainWindow : Window
{
    private StorageService _storageService;
    private readonly PasswordGenerator _passwordGenerator;
    private readonly MainViewModel _viewModel;
    private readonly LocalizationService _localization;
    private readonly VaultManagerService _vaultManager;
    private readonly DispatcherTimer _autoLockTimer;
    private readonly DispatcherTimer _clipboardClearTimer;
    private readonly DispatcherTimer _lockoutTimer;
    private DateTime _lastActivity;
    private bool _isVaultUnlocked;
    private Grid? _previousScreen;
    private string _vaultPath = "";
    private VaultInfo? _selectedVault;

    private const uint WDA_EXCLUDEFROMCAPTURE = 0x00000011;

    [DllImport("user32.dll")]
    private static extern bool SetWindowDisplayAffinity(IntPtr hwnd, uint dwAffinity);

    private const int AutoLockTimeoutMinutes = 1;
    private const int ClipboardClearSeconds = 10;
    private const int LockoutUpdateIntervalMs = 100;

    public MainWindow()
    {
        InitializeComponent();
        
        _localization = LocalizationService.Instance;
        _localization.LanguageChanged += OnLanguageChanged;
        
        _vaultManager = VaultManagerService.Instance;
        
        LoadPathSettings();
        _storageService = new StorageService(_vaultPath);
        _passwordGenerator = new PasswordGenerator();
        _viewModel = new MainViewModel(_storageService);
        DataContext = _viewModel;
        
        _autoLockTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(30)
        };
        _autoLockTimer.Tick += AutoLockTimer_Tick;
        
        _clipboardClearTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(ClipboardClearSeconds)
        };
        _clipboardClearTimer.Tick += ClipboardClearTimer_Tick;
        
        _lockoutTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(LockoutUpdateIntervalMs)
        };
        _lockoutTimer.Tick += LockoutTimer_Tick;
        
        PreviewMouseMove += OnUserActivity;
        PreviewKeyDown += OnUserActivity;
        
        Loaded += MainWindow_Loaded;
        Deactivated += Window_Deactivated;
        Activated += Window_Activated;
        Closing += MainWindow_Closing;
        
        VaultListBox.SelectionChanged += VaultListBox_SelectionChanged;
    }

    private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        // Secure cleanup on window close
        _autoLockTimer.Stop();
        _clipboardClearTimer.Stop();
        _lockoutTimer.Stop();
        
        // Clear master key from memory
        _storageService.ClearMasterKey();
        _storageService.Dispose();
        
        // Clear all credentials securely
        foreach (var cred in _viewModel.Credentials)
        {
            cred.SecureClear();
            cred.Dispose();
        }
        _viewModel.Credentials.Clear();
        
        // Clear all password fields
        ClearAllPasswords();
        
        // Clear clipboard
        try { Clipboard.Clear(); } catch { }
    }

    private void ClearAllPasswords()
    {
        // Master password fields
        UnlockPassword.Password = "";
        CreateMasterPassword.Password = "";
        ConfirmMasterPassword.Password = "";
        
        // Edit form passwords
        EditPassword.Password = "";
        EditPasswordVisible.Text = "";
        EditPassword.Visibility = Visibility.Visible;
        EditPasswordVisible.Visibility = Visibility.Collapsed;
        ShowEditPasswordBtn.Content = "👁️";
        
        // Generated password
        GeneratedPassword.Text = "";
    }

    private void OnUserActivity(object sender, EventArgs e)
    {
        if (_isVaultUnlocked)
        {
            ResetAutoLockTimer();
        }
    }

    private void Window_Deactivated(object? sender, EventArgs e)
    {
        if (_isVaultUnlocked)
        {
            _autoLockTimer.Stop();
        }
    }

    private void Window_Activated(object? sender, EventArgs e)
    {
        if (_isVaultUnlocked)
        {
            if ((DateTime.Now - _lastActivity).TotalMinutes >= AutoLockTimeoutMinutes)
            {
                LockVault();
            }
            else
            {
                ResetAutoLockTimer();
            }
        }
    }

    private void ResetAutoLockTimer()
    {
        _lastActivity = DateTime.Now;
        _autoLockTimer.Stop();
        _autoLockTimer.Start();
    }

    private void AutoLockTimer_Tick(object? sender, EventArgs e)
    {
        if ((DateTime.Now - _lastActivity).TotalMinutes >= AutoLockTimeoutMinutes)
        {
            LockVault();
        }
    }

    private void ClipboardClearTimer_Tick(object? sender, EventArgs e)
    {
        _clipboardClearTimer.Stop();
        
        try
        {
            Clipboard.Clear();
            StatusMessage.Text = _localization["ClipboardCleared"];
            _storageService.LogClipboardCleared();
        }
        catch { }
    }

    private string FormatLockoutTime(int totalSeconds)
    {
        if (totalSeconds >= 60)
        {
            var minutes = totalSeconds / 60;
            var seconds = totalSeconds % 60;
            if (seconds > 0)
            {
                return $"{_localization.GetFormatted("LockoutMinutes", minutes)} {_localization.GetFormatted("LockoutSeconds", seconds)}";
            }
            return _localization.GetFormatted("LockoutMinutes", minutes);
        }
        return _localization.GetFormatted("LockoutSeconds", totalSeconds);
    }

    private void LockoutTimer_Tick(object? sender, EventArgs e)
    {
        if (_storageService.IsLockedOut(out int remainingSeconds))
        {
            LoginStatusMessage.Text = _localization.GetFormatted("LockoutMessage", FormatLockoutTime(remainingSeconds));
        }
        else
        {
            StopLockout();
        }
    }

    private void StartLockout(int seconds)
    {
        LoginStatusMessage.Text = _localization.GetFormatted("LockoutMessage", FormatLockoutTime(seconds));
        
        UnlockBtn.IsEnabled = false;
        UnlockPassword.IsEnabled = false;
        CreateVaultBtn.IsEnabled = false;
        CreateMasterPassword.IsEnabled = false;
        ConfirmMasterPassword.IsEnabled = false;
        
        _lockoutTimer.Start();
    }

    private void StopLockout()
    {
        _lockoutTimer.Stop();
        
        UnlockBtn.IsEnabled = true;
        UnlockPassword.IsEnabled = true;
        CreateVaultBtn.IsEnabled = true;
        CreateMasterPassword.IsEnabled = true;
        ConfirmMasterPassword.IsEnabled = true;
        
        LoginStatusMessage.Text = "";
    }

    private void LockVault()
    {
        _isVaultUnlocked = false;
        _autoLockTimer.Stop();
        _clipboardClearTimer.Stop();
        _lockoutTimer.Stop();
        
        _storageService.ClearMasterKey();
        
        foreach (var cred in _viewModel.Credentials)
        {
            cred.SecureClear();
            cred.Dispose();
        }
        _viewModel.Credentials.Clear();
        _viewModel.FilterCredentials();
        _viewModel.SelectedCredential = null;
        
        ClearAllPasswords();
        
        LoginScreen.Visibility = Visibility.Visible;
        MainApp.Visibility = Visibility.Collapsed;
        SettingsPanel.Visibility = Visibility.Collapsed;
        LoginStatusMessage.Text = "";
        _selectedVault = null;
        ShowVaultSelection();
    }

    private void SwitchToMainApp()
    {
        SettingsPanel.Visibility = Visibility.Collapsed;
        LoginScreen.Visibility = Visibility.Visible;
        _previousScreen = null;
    }

    private void OnLanguageChanged()
    {
        UpdateUIText();
        
        // Update status message to reflect current credential count
        if (_isVaultUnlocked)
        {
            StatusMessage.Text = _localization.GetFormatted("CredentialsStored", _viewModel.Credentials.Count);
        }
    }

    private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            Maximize_Click(sender, e);
        }
        else if (e.LeftButton == MouseButtonState.Pressed)
        {
            DragMove();
        }
    }

    private void PreventScreenCapture()
    {
        try
        {
            var handle = new WindowInteropHelper(this).Handle;
            SetWindowDisplayAffinity(handle, WDA_EXCLUDEFROMCAPTURE);
        }
        catch
        {
        }
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        PreventScreenCapture();
        UpdateMaximizeButton();
        UpdateUIText();
        RefreshVaultList();
        
        if (_storageService.IsLockedOut(out int remainingSeconds))
        {
            StartLockout(remainingSeconds);
        }
        
        if (_isVaultUnlocked)
        {
            ShowMainApp();
        }
        else
        {
            ShowNoSelection();
        }
    }

    private void Window_StateChanged(object sender, EventArgs e)
    {
        UpdateMaximizeButton();
    }

    private void UpdateMaximizeButton()
    {
        if (WindowState == WindowState.Maximized)
        {
            MaximizeBtn.Content = "\u2752";
        }
        else
        {
            MaximizeBtn.Content = "\u25A1";
        }
    }

    private void Minimize_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void Maximize_Click(object sender, RoutedEventArgs e)
    {
        if (WindowState == WindowState.Maximized)
        {
            WindowState = WindowState.Normal;
        }
        else
        {
            WindowState = WindowState.Maximized;
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void UpdateUIText()
    {
        var loc = _localization;

        // Login screen
        AppSubtitle.Text = loc["AppSubtitle"];
        CreateVaultTitle.Text = loc["CreateMasterPassword"];
        CreateVaultMasterPassLabel.Text = loc["MasterPassword"];
        CreateVaultConfirmLabel.Text = loc["ConfirmPassword"];
        CreateVaultBtn.Content = loc["CreateVault"];
        UnlockTitle.Text = loc["WelcomeBack"];
        UnlockMasterPassLabel.Text = loc["MasterPassword"];
        UnlockBtn.Content = loc["UnlockVault"];

        // Main menu
        SearchBox.Text = "";
        SearchBox.Tag = loc["SearchCredentials"];
        AddNewBtn.Content = loc["AddNew"];
        LockBtn.Content = loc["LockVault"];
        
        // Status bar
        StatusMessage.Text = loc.GetFormatted("CredentialsStored", _viewModel.Credentials.Count);

        // No selection
        NoSelectionTitle.Text = loc["SelectCredential"];
        NoSelectionHint.Text = loc["SelectItemHint"];

        // Details
        EditBtn.ToolTip = loc["Edit"];
        DeleteBtn.ToolTip = loc["Delete"];
        UsernameLabel.Text = loc["Username"];
        EmailLabel.Text = loc["Email"];
        PasswordLabel.Text = loc["Password"];
        WebsiteLabel.Text = loc["Website"];
        NotesLabel.Text = loc["Notes"];
        NotesDefault.Text = loc["NoNotes"];
        CreatedPrefix.Text = loc["Created"] + ":";
        ModifiedPrefix.Text = loc["Modified"] + ":";

        // Add/Edit panel
        PanelTitle.Text = loc["AddNewCredential"];
        TitleLabel.Text = loc["TitleRequired"];
        UsernameEditLabel.Text = loc["Username"];
        EmailEditLabel.Text = loc["Email"];
        PasswordEditLabel.Text = loc["Password"];
        WebsiteEditLabel.Text = loc["Website"];
        NotesEditLabel.Text = loc["Notes"];
        GeneratorTitle.Text = loc["PasswordGenerator"];
        ChkLowercase.Content = loc["Lowercase"];
        ChkUppercase.Content = loc["Uppercase"];
        ChkDigits.Content = loc["Numbers"];
        ChkSpecial.Content = loc["SpecialChars"];
        UsePasswordBtn.Content = loc["UsePassword"];
        CancelBtn.Content = loc["Cancel"];
        SaveBtn.Content = loc["Save"];

        // Settings
        SettingsTitle.Text = loc["Settings"];
        SettingsInterfaceTitle.Text = loc["Interface"];
        SettingsLanguageLabel.Text = loc["Lang"];
        SettingsFileLocationTitle.Text = loc["FileLocation"];
        VaultPathDescription.Text = loc["VaultPathDesc"];
        VaultPathBrowseBtn.Content = loc["Browse"];
        VaultPathResetBtn.Content = loc["ResetDefault"];
        SettingsLoggingTitle.Text = loc["Logging"];
        LoggingEnabledLabel.Text = loc["EnableLogging"];
        OpenLogsFolderBtn.Content = loc["OpenLogsFolder"];
        ClearLogsBtn.Content = loc["ClearLogs"];
        SettingsImportExportTitle.Text = loc["ImportExport"];
        SettingsDeleteVaultTitle.Text = loc["DeleteCurrentVault"];
        DeleteVaultBtn.Content = loc["DeleteCurrentVault"];
        ExportVaultBtn.Content = loc["ExportVault"];
        ImportVaultBtn.Content = loc["ImportVault"];
        DialogOkBtn.Content = _localization["OK"];
        DialogCancelBtn.Content = _localization["Cancel"];
        DialogTitle.Text = loc["Warning"];
        SelectVaultTitle.Text = loc["SelectVault"];
        CreateNewVaultBtn.Content = "+ " + loc["CreateNewVault"];
        NoVaultsMessage.Text = loc["NoVaults"];
        VaultNameLabel.Text = loc["VaultName"];
        CreateVaultTitle.Text = loc["CreateNewVault"];
        CreateVaultBtn.Content = loc["CreateVault"];
        CancelCreateBtn.Content = loc["Cancel"];
        UnlockTitle.Text = loc["WelcomeBack"];
        UnlockBtn.Content = loc["UnlockVault"];
        BackToVaultsBtn.Content = loc["Cancel"];
    }

    private void RefreshVaultList()
    {
        var vaults = _vaultManager.GetAllVaults();
        VaultListBox.ItemsSource = null;
        VaultListBox.ItemsSource = vaults;

        if (vaults.Count == 0)
        {
            NoVaultsMessage.Visibility = Visibility.Visible;
            CreateNewVaultBtn.Visibility = Visibility.Visible;
        }
        else
        {
            NoVaultsMessage.Visibility = Visibility.Collapsed;
            CreateNewVaultBtn.Visibility = Visibility.Visible;
        }
    }

    private void ShowCreateVaultForm_Click(object sender, RoutedEventArgs e)
    {
        VaultSelectionPanel.Visibility = Visibility.Collapsed;
        CreateVaultForm.Visibility = Visibility.Visible;
        UnlockForm.Visibility = Visibility.Collapsed;
        LoginStatusMessage.Text = "";
        NewVaultName.Text = "";
        CreateMasterPassword.Password = "";
        ConfirmMasterPassword.Password = "";
    }

    private void CancelCreateVault_Click(object sender, RoutedEventArgs e)
    {
        ShowVaultSelection();
    }

    private void ShowVaultSelection()
    {
        LoginScreen.Visibility = Visibility.Visible;
        MainApp.Visibility = Visibility.Collapsed;
        SettingsPanel.Visibility = Visibility.Collapsed;
        VaultSelectionPanel.Visibility = Visibility.Visible;
        CreateVaultForm.Visibility = Visibility.Collapsed;
        UnlockForm.Visibility = Visibility.Collapsed;
        LoginStatusMessage.Text = "";
        _selectedVault = null;
        RefreshVaultList();
    }

    private void BackToVaults_Click(object sender, RoutedEventArgs e)
    {
        ShowVaultSelection();
    }

    private void VaultListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (VaultListBox.SelectedItem is VaultInfo vault)
        {
            _selectedVault = vault;
            _vaultPath = vault.Path;
            _storageService.Dispose();
            _storageService = new StorageService(_vaultPath);
            _viewModel.UpdateStorageService(_storageService);

            _vaultManager.UpdateLastOpened(vault.Id);

            SelectedVaultNameLabel.Text = vault.Name;

            VaultSelectionPanel.Visibility = Visibility.Collapsed;
            CreateVaultForm.Visibility = Visibility.Collapsed;
            UnlockForm.Visibility = Visibility.Visible;
            LoginStatusMessage.Text = "";
            UnlockPassword.Password = "";

            CheckVaultState();
        }
    }

    private void DeleteVaultBtn_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string vaultId)
        {
            var vault = _vaultManager.GetVaultById(vaultId);
            if (vault != null)
            {
                var loc = _localization;
                ShowConfirmDialog(loc["DeleteVault"], string.Format(loc["DeleteVaultConfirm"], vault.Name), () =>
                {
                    _vaultManager.DeleteVault(vaultId);
                    RefreshVaultList();
                });
            }
        }
    }

    private void CheckVaultState()
    {
        if (_storageService.VaultExists())
        {
            CreateVaultForm.Visibility = Visibility.Collapsed;
            UnlockForm.Visibility = Visibility.Visible;
        }
        else
        {
            CreateVaultForm.Visibility = Visibility.Visible;
            UnlockForm.Visibility = Visibility.Collapsed;
        }
    }

    private void CreateVault_Click(object sender, RoutedEventArgs e)
    {
        var vaultName = NewVaultName.Text.Trim();
        var masterPassword = CreateMasterPassword.Password;
        var confirmPassword = ConfirmMasterPassword.Password;
        var loc = _localization;
        
        if (string.IsNullOrEmpty(vaultName))
        {
            LoginStatusMessage.Text = loc["VaultNameRequired"];
            return;
        }

        var existingVaults = _vaultManager.GetAllVaults();
        if (existingVaults.Any(v => v.Name.Equals(vaultName, StringComparison.OrdinalIgnoreCase)))
        {
            LoginStatusMessage.Text = loc["VaultNameExists"];
            return;
        }
        
        if (string.IsNullOrEmpty(masterPassword))
        {
            LoginStatusMessage.Text = loc["PasswordRequired"];
            return;
        }

        if (masterPassword.Length < 8)
        {
            LoginStatusMessage.Text = loc["PasswordTooShort"];
            return;
        }

        if (masterPassword != confirmPassword)
        {
            LoginStatusMessage.Text = loc["PasswordsMismatch"];
            return;
        }

        var vaultPath = Path.Combine(_vaultPath, vaultName);
        var vault = _vaultManager.CreateVault(vaultName, vaultPath);

        _storageService.Dispose();
        _storageService = new StorageService(vaultPath);
        _viewModel.UpdateStorageService(_storageService);
        _vaultPath = vaultPath;
        _selectedVault = vault;

        _storageService.CreateVault(masterPassword);
        
        // Securely clear password from memory
        masterPassword = "";
        CreateMasterPassword.Password = "";
        ConfirmMasterPassword.Password = "";
        
        _viewModel.Credentials.Clear();
        _viewModel.FilterCredentials();
        ShowMainApp();
    }

    private void Unlock_Click(object sender, RoutedEventArgs e)
    {
        var masterPassword = UnlockPassword.Password;
        
        if (string.IsNullOrEmpty(masterPassword))
        {
            LoginStatusMessage.Text = _localization["EnterMasterPassword"];
            return;
        }

        var (success, errorMessage, remainingSeconds) = _storageService.VerifyPassword(masterPassword);
        if (!success)
        {
            if (remainingSeconds > 0)
            {
                StartLockout(remainingSeconds);
            }
            else
            {
                LoginStatusMessage.Text = errorMessage ?? _localization["IncorrectPassword"];
            }
            return;
        }

        try
        {
            _storageService.Initialize(masterPassword);
            var credentials = _storageService.LoadVault();
            
            // Clear password immediately after use
            masterPassword = "";
            UnlockPassword.Password = "";
            
            _viewModel.Credentials.Clear();
            foreach (var cred in credentials)
            {
                _viewModel.Credentials.Add(cred);
            }
            
            _viewModel.FilterCredentials();
            ShowMainApp();
        }
        catch (InvalidOperationException ex)
        {
            if (ex.Message.Contains("integrity") || ex.Message.Contains("tampered"))
            {
                LoginStatusMessage.Text = _localization["VaultTampered"];
            }
            else
            {
                LoginStatusMessage.Text = _localization["DecryptionFailed"];
            }
        }
        catch (Exception)
        {
            LoginStatusMessage.Text = _localization["DecryptionFailed"];
        }
    }

    private void ShowMainApp()
    {
        _isVaultUnlocked = true;
        ResetAutoLockTimer();
        
        LoginScreen.Visibility = Visibility.Collapsed;
        MainApp.Visibility = Visibility.Visible;
        SettingsPanel.Visibility = Visibility.Collapsed;
        
        // Reset view to show only the credentials list
        AddEditPanel.Visibility = Visibility.Collapsed;
        CredentialDetails.Visibility = Visibility.Collapsed;
        NoSelectionPanel.Visibility = Visibility.Visible;
        
        _viewModel.FilterCredentials();
        _viewModel.SelectedCredential = null;
        
        StatusMessage.Text = _localization.GetFormatted("CredentialsStored", _viewModel.Credentials.Count);
    }

    private void Lock_Click(object sender, RoutedEventArgs e)
    {
        LockVault();
    }

    private void AddCredential_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.StartAddCredential();
        PanelTitle.Text = _localization["AddNewCredential"];
        ClearEditForm();
        AddEditPanel.Visibility = Visibility.Visible;
        NoSelectionPanel.Visibility = Visibility.Collapsed;
        CredentialDetails.Visibility = Visibility.Collapsed;
        MainSettingsBtn.Visibility = Visibility.Collapsed;
    }

    private void EditCredential_Click(object sender, RoutedEventArgs e)
    {
        var credential = _viewModel.SelectedCredential;
        if (credential == null) return;

        _viewModel.StartEditCredential();
        PanelTitle.Text = _localization["EditCredential"];
        
        EditTitle.Text = credential.Title;
        EditUsername.Text = credential.Username;
        EditEmail.Text = credential.Email;
        EditPassword.Password = credential.Password;
        EditPasswordVisible.Text = credential.Password;
        EditPassword.Visibility = Visibility.Visible;
        EditPasswordVisible.Visibility = Visibility.Collapsed;
        ShowEditPasswordBtn.Content = "👁️";
        EditWebsite.Text = credential.Website;
        EditNotes.Text = credential.Notes;
        
        AddEditPanel.Visibility = Visibility.Visible;
        NoSelectionPanel.Visibility = Visibility.Collapsed;
        CredentialDetails.Visibility = Visibility.Collapsed;
        MainSettingsBtn.Visibility = Visibility.Collapsed;
    }

    private void DeleteCredential_Click(object sender, RoutedEventArgs e)
    {
        var credential = _viewModel.SelectedCredential;
        if (credential == null) return;

        var title = credential.Title;

        ShowConfirmDialog(
            _localization["ConfirmDelete"],
            string.Format(_localization["ConfirmDeleteMessage"], title),
            () =>
            {
                _viewModel.DeleteSelectedCredential();
                ShowNoSelection();
                StatusMessage.Text = _localization.GetFormatted("CredentialDeleted", title);
            });
    }

    private void SaveCredential_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(EditTitle.Text))
        {
            StatusMessage.Text = _localization["TitleRequiredError"];
            return;
        }

        var password = "";
        if (EditPassword.Visibility == Visibility.Visible)
        {
            password = EditPassword.Password ?? "";
        }
        else
        {
            password = EditPasswordVisible.Text ?? "";
        }

        var credential = new Credential
        {
            Title = EditTitle.Text.Trim(),
            Username = EditUsername.Text?.Trim() ?? "",
            Email = EditEmail.Text?.Trim() ?? "",
            Password = password,
            Website = EditWebsite.Text?.Trim() ?? "",
            Notes = EditNotes.Text?.Trim() ?? ""
        };

        // Clear password from memory immediately
        password = "";

        var saved = _viewModel.SaveCredential(credential);
        
        if (saved)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                ClosePanel_Click(sender, e);
                StatusMessage.Text = _localization["CredentialSaved"];
            }), System.Windows.Threading.DispatcherPriority.Background);
        }
        else
        {
            StatusMessage.Text = "Failed to save credential";
        }
    }

    private void CancelEdit_Click(object sender, RoutedEventArgs e)
    {
        ClosePanel_Click(sender, e);
    }

    private void ClosePanel_Click(object sender, RoutedEventArgs e)
    {
        AddEditPanel.Visibility = Visibility.Collapsed;
        ClearEditForm();
        
        _viewModel.FilterCredentials();
        
        if (_viewModel.SelectedCredential != null)
        {
            ShowCredentialDetails();
        }
        else
        {
            ShowNoSelection();
        }
    }

    private void ClearEditForm()
    {
        EditTitle.Text = "";
        EditUsername.Text = "";
        EditEmail.Text = "";
        EditPassword.Password = "";
        EditPasswordVisible.Text = "";
        EditPassword.Visibility = Visibility.Visible;
        EditPasswordVisible.Visibility = Visibility.Collapsed;
        ShowEditPasswordBtn.Content = "👁️";
        EditWebsite.Text = "";
        EditNotes.Text = "";
    }

    private void ToggleGenerator_Click(object sender, RoutedEventArgs e)
    {
        if (GeneratorPanel == null)
            return;

        if (GeneratorPanel.Visibility == Visibility.Visible)
        {
            GeneratorPanel.Visibility = Visibility.Collapsed;
        }
        else
        {
            GeneratorPanel.Visibility = Visibility.Visible;
            GeneratePassword();
        }
    }

    private void GeneratePassword()
    {
        if (GeneratorPanel == null || ChkLowercase == null || ChkUppercase == null || 
            ChkDigits == null || ChkSpecial == null || PasswordLengthSlider == null ||
            GeneratedPassword == null || LengthLabel == null || StrengthFill == null || StrengthLabel == null)
            return;

        var length = (int)PasswordLengthSlider.Value;
        var password = _passwordGenerator.Generate(
            length,
            ChkLowercase.IsChecked == true,
            ChkUppercase.IsChecked == true,
            ChkDigits.IsChecked == true,
            ChkSpecial.IsChecked == true);

        GeneratedPassword.Text = password;
        UpdateStrengthIndicator(password);
    }

    private void PasswordLength_Changed(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (LengthLabel == null || GeneratorPanel == null)
            return;
        LengthLabel.Text = $"{(int)e.NewValue}";
        GeneratePassword();
    }

    private void GeneratorOption_Changed(object sender, RoutedEventArgs e)
    {
        GeneratePassword();
    }

    private void UpdateStrengthIndicator(string password)
    {
        if (StrengthFill == null || StrengthLabel == null)
            return;

        var result = _passwordGenerator.AnalyzeStrength(password);
        
        var (label, fillPercent, color) = result.Score switch
        {
            >= 80 => (_localization["Strong"], 100, System.Windows.Media.Color.FromRgb(34, 197, 94)),   //(63, 185, 80)
            >= 60 => (_localization["Good"], 75, System.Windows.Media.Color.FromRgb(252, 186, 3)),      //(88, 166, 255)
            >= 40 => (_localization["Fair"], 50, System.Windows.Media.Color.FromRgb(255, 140, 0)),      //(219, 151, 50)
            _ => (_localization["Weak"], 25, System.Windows.Media.Color.FromRgb(220, 38, 52))           //(218, 54, 51)
        };
        
        StrengthLabel.Text = label;
        StrengthFill.Background = new System.Windows.Media.SolidColorBrush(color);
        StrengthLabel.Foreground = new System.Windows.Media.SolidColorBrush(color);
        
        StrengthLabel.Measure(new System.Windows.Size(double.PositiveInfinity, double.PositiveInfinity));
        var textWidth = StrengthLabel.DesiredSize.Width;
        var availableWidth = Math.Max(0, StrengthGrid.ActualWidth - textWidth - 4);
        StrengthFill.Width = availableWidth * fillPercent / 100.0;
    }

    private void StrengthGrid_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (_passwordGenerator != null && GeneratedPassword != null)
        {
            var result = _passwordGenerator.AnalyzeStrength(GeneratedPassword.Text ?? "");
            var fillPercent = result.Score >= 80 ? 100 : result.Score >= 60 ? 75 : result.Score >= 40 ? 50 : 25;
            
            StrengthLabel.Measure(new System.Windows.Size(double.PositiveInfinity, double.PositiveInfinity));
            var textWidth = StrengthLabel.DesiredSize.Width;
            var availableWidth = Math.Max(0, StrengthGrid.ActualWidth - textWidth - 4);
            StrengthFill.Width = availableWidth * fillPercent / 100.0;
        }
    }

    private void UseGenerated_Click(object sender, RoutedEventArgs e)
    {
        if (GeneratedPassword == null || EditPassword == null || GeneratorPanel == null)
            return;

        if (!string.IsNullOrEmpty(GeneratedPassword.Text))
        {
            EditPassword.Password = GeneratedPassword.Text;
            EditPasswordVisible.Text = GeneratedPassword.Text;
            GeneratorPanel.Visibility = Visibility.Collapsed;
        }
    }

    private void ShowPassword_Click(object sender, RoutedEventArgs e)
    {
        var credential = _viewModel.SelectedCredential;
        if (credential != null)
        {
            _viewModel.TogglePasswordVisibility();
            PasswordText.Text = _viewModel.IsPasswordVisible ? credential.Password : new string('•', Math.Min(credential.Password.Length, 16));
            ShowPasswordBtn.Content = _viewModel.IsPasswordVisible ? "🙈" : "👁️";
        }
    }

    private void ShowEditPassword_Click(object sender, RoutedEventArgs e)
    {
        if (EditPassword == null || EditPasswordVisible == null) return;
        
        if (EditPassword.Visibility == Visibility.Visible)
        {
            EditPasswordVisible.Text = EditPassword.Password;
            EditPassword.Visibility = Visibility.Collapsed;
            EditPasswordVisible.Visibility = Visibility.Visible;
            ShowEditPasswordBtn.Content = "🙈";
        }
        else
        {
            EditPassword.Password = EditPasswordVisible.Text;
            EditPasswordVisible.Visibility = Visibility.Collapsed;
            EditPassword.Visibility = Visibility.Visible;
            ShowEditPasswordBtn.Content = "👁️";
        }
    }

    private void RegeneratePassword_Click(object sender, RoutedEventArgs e)
    {
        GeneratePassword();
    }

    private void CopyUsername_Click(object sender, RoutedEventArgs e)
    {
        var credential = _viewModel.SelectedCredential;
        if (credential != null)
        {
            var username = !string.IsNullOrEmpty(credential.Username) ? credential.Username : credential.Email;
            if (!string.IsNullOrEmpty(username))
            {
                Clipboard.SetText(username);
                StatusMessage.Text = _localization["UsernameCopied"];
                StartClipboardClearTimer();
            }
        }
    }

    private void CopyEmail_Click(object sender, RoutedEventArgs e)
    {
        var credential = _viewModel.SelectedCredential;
        if (credential != null && !string.IsNullOrEmpty(credential.Email))
        {
            Clipboard.SetText(credential.Email);
            StatusMessage.Text = _localization["EmailCopied"];
            StartClipboardClearTimer();
        }
    }

    private void CopyWebsite_Click(object sender, RoutedEventArgs e)
    {
        var credential = _viewModel.SelectedCredential;
        if (credential != null && !string.IsNullOrEmpty(credential.Website))
        {
            Clipboard.SetText(credential.Website);
            StatusMessage.Text = _localization["WebsiteCopied"];
            StartClipboardClearTimer();
        }
    }

    private void CopyPassword_Click(object sender, RoutedEventArgs e)
    {
        var credential = _viewModel.SelectedCredential;
        if (credential != null)
        {
            Clipboard.SetText(credential.Password);
            StatusMessage.Text = _localization["PasswordCopied"];
            StartClipboardClearTimer();
        }
    }

    private void StartClipboardClearTimer()
    {
        _clipboardClearTimer.Stop();
        _clipboardClearTimer.Start();
    }

    private void CredentialsList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (AddEditPanel.Visibility == Visibility.Visible)
        {
            AddEditPanel.Visibility = Visibility.Collapsed;
        }
        
        if (_viewModel.SelectedCredential != null)
        {
            ShowCredentialDetails();
        }
        else
        {
            ShowNoSelection();
        }
    }

    private void ShowCredentialDetails()
    {
        var credential = _viewModel.SelectedCredential;
        if (credential != null)
        {
            NoSelectionPanel.Visibility = Visibility.Collapsed;
            CredentialDetails.Visibility = Visibility.Visible;
            MainSettingsBtn.Visibility = Visibility.Collapsed;
            
            UsernameText.Text = credential.Username;
            EmailText.Text = credential.Email;
            PasswordText.Text = new string('•', Math.Min(credential.Password.Length, 16));
            WebsiteText.Text = credential.Website;
            
            if (string.IsNullOrEmpty(credential.Notes))
            {
                NotesText.Visibility = Visibility.Collapsed;
                NotesDefault.Visibility = Visibility.Visible;
            }
            else
            {
                NotesText.Visibility = Visibility.Visible;
                NotesDefault.Visibility = Visibility.Collapsed;
                NotesText.Text = credential.Notes;
            }
            
            CreatedText.Text = credential.CreatedAt.ToString("MMM dd, yyyy HH:mm");
            ModifiedText.Text = credential.ModifiedAt.ToString("MMM dd, yyyy HH:mm");
            
            _viewModel.IsPasswordVisible = false;
            ShowPasswordBtn.Content = "👁️";
        }
    }

    private void ShowNoSelection()
    {
        NoSelectionPanel.Visibility = Visibility.Visible;
        CredentialDetails.Visibility = Visibility.Collapsed;
        MainSettingsBtn.Visibility = Visibility.Visible;
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _viewModel.SearchQuery = SearchBox.Text ?? "";
    }

    private void Logo_Click(object sender, RoutedEventArgs e)
    {
        if (AddEditPanel.Visibility == Visibility.Visible)
        {
            ClosePanel_Click(sender, e);
        }
        else
        {
            _viewModel.SelectedCredential = null;
            ShowNoSelection();
        }
    }

    private void SettingsBtn_Click(object sender, RoutedEventArgs e)
    {
        if (LoginScreen.Visibility == Visibility.Visible)
        {
            _previousScreen = LoginScreen;
        }
        else
        {
            _previousScreen = MainApp;
        }

        LoginScreen.Visibility = Visibility.Collapsed;
        MainApp.Visibility = Visibility.Collapsed;
        SettingsPanel.Visibility = Visibility.Visible;

        InitializeSettings();
    }

    private void InitializeSettings()
    {
        LanguageComboBox.Items.Clear();
        LanguageComboBox.Items.Add(new ComboBoxItem { Content = "English", Tag = "en" });
        LanguageComboBox.Items.Add(new ComboBoxItem { Content = "Русский", Tag = "ru" });

        var currentLang = _localization.CurrentLanguage;
        foreach (ComboBoxItem item in LanguageComboBox.Items)
        {
            if (item.Tag is string lang && lang == currentLang)
            {
                LanguageComboBox.SelectedItem = item;
                break;
            }
        }

        LoadPathSettings();
        LoggingEnabledCheckBox.IsChecked = AuditService.LoggingEnabled;
    }

    private void LanguageComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (LanguageComboBox.SelectedItem is ComboBoxItem item && item.Tag is string lang)
        {
            if (lang != _localization.CurrentLanguage)
            {
                _localization.CurrentLanguage = lang;
            }
        }
    }

    private void SettingsBackBtn_Click(object sender, RoutedEventArgs e)
    {
        ApplyPathChanges();
        ShowVaultSelection();
    }

    private void VaultPathBrowseBtn_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog();
        if (dialog.ShowDialog() == true)
        {
            VaultPathTextBox.Text = dialog.FolderName;
            SavePathSettings();
            ApplyPathChanges();
        }
    }

    private void VaultPathResetBtn_Click(object sender, RoutedEventArgs e)
    {
        var defaultPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CipherVault");
        VaultPathTextBox.Text = defaultPath;
        SavePathSettings();
        ApplyPathChanges();
    }

    private Action? _dialogConfirmAction;

    private void ShowDialog(string title, string message)
    {
        DialogTitle.Text = title;
        DialogMessage.Text = message;
        DialogCancelBtn.Visibility = Visibility.Collapsed;
        DialogOkBtn.Visibility = Visibility.Visible;
        DialogOkBtn.Content = _localization["OK"];
        DialogOverlay.Visibility = Visibility.Visible;
        DialogOverlay.KeyDown += DialogOverlay_KeyDown;
        _dialogConfirmAction = null;
        DialogOkBtn.Focus();
    }

    private void ShowConfirmDialog(string title, string message, Action onConfirm)
    {
        DialogTitle.Text = title;
        DialogMessage.Text = message;
        DialogCancelBtn.Visibility = Visibility.Visible;
        DialogCancelBtn.Content = _localization["Cancel"];
        DialogOkBtn.Content = _localization["Confirm"];
        DialogOverlay.Visibility = Visibility.Visible;
        DialogOverlay.KeyDown += DialogOverlay_KeyDown;
        _dialogConfirmAction = onConfirm;
        DialogOkBtn.Focus();
    }

    private void DialogOverlay_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            DialogCancelBtn_Click(sender, e);
        }
        else if (e.Key == Key.Enter)
        {
            DialogOkBtn_Click(sender, e);
        }
    }

    private void DialogOkBtn_Click(object sender, RoutedEventArgs e)
    {
        DialogOverlay.KeyDown -= DialogOverlay_KeyDown;
        DialogOverlay.Visibility = Visibility.Collapsed;
        DialogOkBtn.Content = _localization["OK"];
        DialogOkBtn.Width = 140;
        DialogCancelBtn.Width = 140;
        DialogVaultComboBox.Visibility = Visibility.Collapsed;
        _dialogConfirmAction?.Invoke();
        _dialogConfirmAction = null;
        _exportAction?.Invoke();
        _exportAction = null;
    }

    private void DialogCancelBtn_Click(object sender, RoutedEventArgs e)
    {
        DialogOverlay.KeyDown -= DialogOverlay_KeyDown;
        DialogOverlay.Visibility = Visibility.Collapsed;
        DialogOkBtn.Content = _localization["OK"];
        DialogOkBtn.Width = 140;
        DialogCancelBtn.Width = 140;
        DialogVaultComboBox.Visibility = Visibility.Collapsed;
        _dialogConfirmAction = null;
        _exportAction = null;
    }

    private void LoggingEnabledCheckBox_Changed(object sender, RoutedEventArgs e)
    {
        AuditService.LoggingEnabled = LoggingEnabledCheckBox.IsChecked == true;
    }

    private void OpenLogsFolderBtn_Click(object sender, RoutedEventArgs e)
    {
        var logsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CipherVault", "Logs");
        if (!Directory.Exists(logsPath))
        {
            Directory.CreateDirectory(logsPath);
        }
        System.Diagnostics.Process.Start("explorer.exe", logsPath);
    }

    private void DeleteCurrentVaultBtn_Click(object sender, RoutedEventArgs e)
    {
        var loc = _localization;
        ShowConfirmDialog(loc["DeleteCurrentVault"], loc["DeleteVaultWarning"], () =>
        {
            try
            {
                var vaultPath = _vaultPath;
                if (Directory.Exists(vaultPath))
                {
                    Directory.Delete(vaultPath, true);
                }

                if (_selectedVault != null)
                {
                    _vaultManager.DeleteVault(_selectedVault.Id);
                    _selectedVault = null;
                }

                _storageService.Dispose();
                _storageService = new StorageService(_vaultPath);
                _viewModel.UpdateStorageService(_storageService);

                ShowDialog(loc["DeleteCurrentVault"], loc["VaultDeleted"]);
                ShowVaultSelection();
            }
            catch
            {
                ShowDialog(loc["DeleteCurrentVault"], loc["ImportFailed"]);
            }
        });
    }

    private void ClearLogsBtn_Click(object sender, RoutedEventArgs e)
    {
        var loc = _localization;
        ShowConfirmDialog(loc["ClearLogs"], loc["ConfirmClearLogs"], () =>
        {
            AuditService.Instance?.ClearLogs();
            ShowDialog(loc["ClearLogs"], loc["LogsClearedSuccess"]);
        });
    }

    private Action? _exportAction;

    private void ExportVaultBtn_Click(object sender, RoutedEventArgs e)
    {
        var loc = _localization;
        var vaults = _vaultManager.GetAllVaults();

        if (vaults.Count == 0)
        {
            ShowDialog(loc["ExportVault"], loc["NoVaults"]);
            return;
        }

        if (vaults.Count == 1)
        {
            DoExportVault(vaults[0], loc);
            return;
        }

        DialogTitle.Text = loc["ExportVault"];
        DialogMessage.Text = loc["SelectVault"];
        DialogVaultComboBox.Visibility = Visibility.Visible;
        DialogCancelBtn.Visibility = Visibility.Visible;
        DialogCancelBtn.Content = loc["Cancel"];
        DialogOkBtn.Content = loc["Export"];
        DialogOkBtn.Width = 160;
        DialogCancelBtn.Width = 160;

        DialogVaultComboBox.Items.Clear();
        foreach (var v in vaults)
        {
            DialogVaultComboBox.Items.Add(new ComboBoxItem { Content = v.Name, Tag = v });
        }
        DialogVaultComboBox.SelectedIndex = 0;

        DialogOverlay.Visibility = Visibility.Visible;
        DialogOverlay.KeyDown += DialogOverlay_KeyDown;
        _dialogConfirmAction = null;
        _exportAction = () =>
        {
            if (DialogVaultComboBox.SelectedItem is ComboBoxItem item && item.Tag is VaultInfo vaultInfo)
            {
                DoExportVault(vaultInfo, loc);
            }
        };
        DialogVaultComboBox.Focus();
    }

    private void DoExportVault(VaultInfo vaultInfo, LocalizationService loc)
    {
        try
        {
            var saveDialog = new SaveFileDialog
            {
                Filter = $"{loc["ZipFiles"]}|*.zip|{loc["AllFiles"]}|*.*",
                FileName = $"{vaultInfo.Name}.zip",
                DefaultExt = "zip"
            };

            if (saveDialog.ShowDialog() == true)
            {
                var vaultDat = Path.Combine(vaultInfo.Path, "vault.dat");
                var configJson = Path.Combine(vaultInfo.Path, "config.json");

                if (!File.Exists(vaultDat) || !File.Exists(configJson))
                {
                    ShowDialog(loc["ExportVault"], loc["ImportFailed"]);
                    return;
                }

                if (File.Exists(saveDialog.FileName))
                    File.Delete(saveDialog.FileName);

                using (var archive = ZipFile.Open(saveDialog.FileName, ZipArchiveMode.Create))
                {
                    archive.CreateEntryFromFile(vaultDat, "vault.dat");
                    archive.CreateEntryFromFile(configJson, "config.json");
                }

                ShowDialog(loc["ExportVault"], loc["ExportSuccess"]);
            }
        }
        catch
        {
            ShowDialog(loc["ExportVault"], loc["ExportFailed"]);
        }
    }

    private void ImportVaultBtn_Click(object sender, RoutedEventArgs e)
    {
        var loc = _localization;

        var dialog = new OpenFileDialog
        {
            Filter = $"{loc["ZipFiles"]}|*.zip|{loc["AllFiles"]}|*.*",
            Title = loc["SelectImportFile"]
        };

        if (dialog.ShowDialog() == true)
        {
            ImportVault(dialog.FileName, loc);
        }
    }

    private void ImportVault(string sourcePath, LocalizationService loc)
    {
        try
        {
            string tempDir = "";
            string vaultDatPath = "";
            string configJsonPath = "";

            if (sourcePath.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                tempDir = Path.Combine(Path.GetTempPath(), "CipherVault_Import_" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(tempDir);

                ZipFile.ExtractToDirectory(sourcePath, tempDir);

                vaultDatPath = Path.Combine(tempDir, "vault.dat");
                configJsonPath = Path.Combine(tempDir, "config.json");

                if (!File.Exists(vaultDatPath) || !File.Exists(configJsonPath))
                {
                    Directory.Delete(tempDir, true);
                    ShowDialog(loc["ImportVault"], loc["InvalidImportSource"]);
                    return;
                }
            }
            else if (Directory.Exists(sourcePath))
            {
                vaultDatPath = Path.Combine(sourcePath, "vault.dat");
                configJsonPath = Path.Combine(sourcePath, "config.json");

                if (!File.Exists(vaultDatPath) || !File.Exists(configJsonPath))
                {
                    ShowDialog(loc["ImportVault"], loc["InvalidImportSource"]);
                    return;
                }
            }
            else
            {
                ShowDialog(loc["ImportVault"], loc["InvalidImportSource"]);
                return;
            }

            var vaultName = Path.GetFileNameWithoutExtension(sourcePath);

            var existingVaults = _vaultManager.GetAllVaults();
            var baseName = vaultName;
            var counter = 1;
            while (existingVaults.Any(v => v.Name.Equals(vaultName, StringComparison.OrdinalIgnoreCase)))
            {
                vaultName = $"{baseName} ({counter})";
                counter++;
            }

            var vaultPath = Path.Combine(_vaultPath, vaultName);
            Directory.CreateDirectory(vaultPath);

            File.Copy(vaultDatPath, Path.Combine(vaultPath, "vault.dat"), true);
            File.Copy(configJsonPath, Path.Combine(vaultPath, "config.json"), true);

            if (!string.IsNullOrEmpty(tempDir))
            {
                Directory.Delete(tempDir, true);
            }

            _vaultManager.CreateVault(vaultName, vaultPath);

            RefreshVaultList();
            ShowDialog(loc["ImportVault"], loc["ImportSuccess"]);
        }
        catch
        {
            ShowDialog(loc["ImportVault"], loc["ImportFailed"]);
        }
    }

    private void SavePathSettings()
    {
        var defaultConfigPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CipherVault");
        var settingsConfigPath = Path.Combine(defaultConfigPath, "settings.json");
        var config = new Dictionary<string, string>();

        if (File.Exists(settingsConfigPath))
        {
            var json = File.ReadAllText(settingsConfigPath);
            config = JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? new();
        }

        config["vaultPath"] = VaultPathTextBox.Text;
        File.WriteAllText(settingsConfigPath, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
    }

    private void LoadPathSettings()
    {
        var defaultConfigPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CipherVault");
        var settingsConfigPath = Path.Combine(defaultConfigPath, "settings.json");
        var defaultVaultPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CipherVault");

        _vaultPath = defaultVaultPath;

        if (File.Exists(settingsConfigPath))
        {
            var json = File.ReadAllText(settingsConfigPath);
            var config = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            if (config != null)
            {
                if (config.TryGetValue("vaultPath", out var vp) && !string.IsNullOrEmpty(vp))
                    _vaultPath = vp;
            }
        }

        VaultPathTextBox.Text = _vaultPath;
    }

    private void ApplyPathChanges()
    {
        var newVaultPath = VaultPathTextBox.Text;

        if (newVaultPath != _vaultPath)
        {
            if (_isVaultUnlocked)
            {
                var loc = _localization;
                ShowDialog(loc["VaultOpen"], loc["LockVaultBeforePathChange"]);
                LoadPathSettings();
                return;
            }

            _storageService.Dispose();
            _vaultPath = newVaultPath;
            _storageService = new StorageService(_vaultPath);
            _viewModel.UpdateStorageService(_storageService);

            CheckVaultState();

            if (!_storageService.VaultExists())
            {
                var loc = _localization;
                ShowDialog(loc["Warning"], loc["NoVaultAtPath"]);
            }
        }
    }

    private void UnlockPassword_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            Unlock_Click(sender, e);
        }
    }

    private void CreatePassword_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            CreateVault_Click(sender, e);
        }
    }

    private void WebsiteText_MouseDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        var credential = _viewModel.SelectedCredential;
        if (credential != null && !string.IsNullOrEmpty(credential.Website))
        {
            try
            {
                var url = credential.Website;
                if (!url.StartsWith("http://") && !url.StartsWith("https://"))
                {
                    url = "https://" + url;
                }
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });
            }
            catch { }
        }
    }
}
