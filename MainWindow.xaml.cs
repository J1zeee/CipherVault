using System.IO;
using System.Security.Cryptography;
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
    private readonly VaultPaths _vaultPaths;
    private readonly AppSettingsStore _settings;
    private VaultInfo? _selectedVault;


    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowDisplayAffinity(IntPtr hwnd, uint dwAffinity);

    // Cleared once if the OS is older than Windows 10 2004 and cannot exclude from capture.
    private static bool _excludeFromCaptureSupported = true;
    private static bool _screenCaptureProtectionEnabled = true;

    private static uint CurrentCaptureAffinity =>
        ScreenCaptureAffinity.For(_screenCaptureProtectionEnabled, _excludeFromCaptureSupported);

    private const int AutoLockTimeoutMinutes = 1;
    private const int ClipboardClearSeconds = 10;
    private const int LockoutUpdateIntervalMs = 100;

    static MainWindow()
    {
        // Tooltips and context menus are hosted in their own top-level HWNDs, which the
        // affinity set on the main window does not cover. WPF never invokes class
        // handlers for Loaded, so these opening events are the hook; the HWND does not
        // exist yet when they fire, hence the deferred sweep.
        EventManager.RegisterClassHandler(typeof(FrameworkElement),
            FrameworkElement.ToolTipOpeningEvent,
            new ToolTipEventHandler((s, e) => ScheduleCaptureProtectionSweep()));
        EventManager.RegisterClassHandler(typeof(FrameworkElement),
            FrameworkElement.ContextMenuOpeningEvent,
            new ContextMenuEventHandler((s, e) => ScheduleCaptureProtectionSweep()));
    }

    public MainWindow()
    {
        InitializeComponent();
        
        _localization = LocalizationService.Instance;
        _localization.LanguageChanged += OnLanguageChanged;
        
        _vaultManager = VaultManagerService.Instance;
        
        _settings = new AppSettingsStore(GetConfigDirectory());
        // Logging is a persisted preference; it used to reset to off on every start
        // while the checkbox still claimed to remember it.
        AuditService.LoggingEnabled = _settings.GetBool(AppSettingsStore.LoggingEnabledKey);
        _screenCaptureProtectionEnabled =
            _settings.GetBool(AppSettingsStore.ScreenCaptureProtectionKey, defaultValue: true);

        _vaultPaths = new VaultPaths(GetDefaultVaultRoot());
        LoadPathSettings();
        _storageService = new StorageService(_vaultPaths.ActivePath);
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
        
        SourceInitialized += MainWindow_SourceInitialized;
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
        
        // Clear clipboard, but only if it still holds what this app put there.
        SecureClipboard.TryClearOurs();
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
        // The timer deliberately keeps running: losing focus is exactly when an
        // unattended vault should still lock itself.
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
        
        if (SecureClipboard.TryClearOurs())
        {
            StatusMessage.Text = _localization["ClipboardCleared"];
            _storageService.LogClipboardCleared();
        }
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
        // Otherwise the lockout is escaped by stepping back to the list and
        // reselecting the vault.
        BackToVaultsBtn.IsEnabled = false;
        
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
        BackToVaultsBtn.IsEnabled = true;
        
        LoginStatusMessage.Text = "";
    }

    // Drops the master key and every decrypted credential without navigating.
    // Deleting a vault needs this too: the secrets must not outlive the files.
    private void CloseVaultSession()
    {
        _isVaultUnlocked = false;
        _autoLockTimer.Stop();
        _clipboardClearTimer.Stop();

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
    }

    private void LockVault()
    {
        CloseVaultSession();
        _lockoutTimer.Stop();
        
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

    private static bool TrySetCaptureAffinity(IntPtr handle, uint affinity)
    {
        if (handle == IntPtr.Zero)
        {
            return false;
        }

        try
        {
            return SetWindowDisplayAffinity(handle, affinity);
        }
        catch
        {
            return false;
        }
    }

    // Applies the affinity to every HWND the app currently owns, main window included.
    // Idempotent, and the source list is only ever a handful of entries.
    private static void ProtectAllAppWindows()
    {
        foreach (PresentationSource source in PresentationSource.CurrentSources)
        {
            if (source is HwndSource hwndSource && !hwndSource.IsDisposed)
            {
                TrySetCaptureAffinity(hwndSource.Handle, CurrentCaptureAffinity);
            }
        }
    }

    private static void ScheduleCaptureProtectionSweep()
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher == null)
        {
            return;
        }

        // Render priority runs after the popup HWND is created but before it is painted.
        dispatcher.BeginInvoke(DispatcherPriority.Render, new Action(ProtectAllAppWindows));
    }

    private void HookDropDowns()
    {
        // Logical tree rather than visual: it also reaches combo boxes inside panels
        // that are still collapsed, and does not need their templates applied.
        foreach (var comboBox in FindLogicalDescendants<ComboBox>(this))
        {
            comboBox.DropDownOpened -= OnDropDownOpened;
            comboBox.DropDownOpened += OnDropDownOpened;
        }
    }

    private static void OnDropDownOpened(object? sender, EventArgs e)
    {
        // The drop-down HWND already exists here, but sweep again next frame in case
        // WPF recycled it.
        ProtectAllAppWindows();
        ScheduleCaptureProtectionSweep();
    }

    private static IEnumerable<T> FindLogicalDescendants<T>(DependencyObject root) where T : DependencyObject
    {
        foreach (var child in LogicalTreeHelper.GetChildren(root))
        {
            if (child is not DependencyObject node)
            {
                continue;
            }

            if (node is T match)
            {
                yield return match;
            }

            foreach (var nested in FindLogicalDescendants<T>(node))
            {
                yield return nested;
            }
        }
    }

    private void PreventScreenCapture()
    {
        var handle = new WindowInteropHelper(this).Handle;

        if (TrySetCaptureAffinity(handle, CurrentCaptureAffinity))
        {
            return;
        }

        // WDA_EXCLUDEFROMCAPTURE needs Windows 10 2004 (build 19041). On older builds
        // fall back to WDA_MONITOR: capture APIs still get a black window, only DWM
        // thumbnails stay visible.
        if (_excludeFromCaptureSupported
            && _screenCaptureProtectionEnabled
            && TrySetCaptureAffinity(handle, ScreenCaptureAffinity.Monitor))
        {
            _excludeFromCaptureSupported = false;
        }
    }

    private void MainWindow_SourceInitialized(object? sender, EventArgs e)
    {
        // Applied here rather than in Loaded: the HWND exists but nothing has been
        // painted yet, so there is no frame the window can be captured on.
        PreventScreenCapture();
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        HookDropDowns();
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
        SettingsSecurityTitle.Text = loc["SecuritySection"];
        ScreenCaptureProtectionHint.Text = loc["ScreenCaptureProtectionHint"];
        LoggingEnabledLabel.Text = loc["EnableLogging"];
        ScreenCaptureProtectionLabel.Text = loc["ScreenCaptureProtection"];
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
        _vaultPaths.ClearSelection();
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
            _vaultPaths.SelectVault(vault.Path);
            _storageService.Dispose();
            _storageService = new StorageService(_vaultPaths.ActivePath);
            _viewModel.UpdateStorageService(_storageService);

            _vaultManager.UpdateLastOpened(vault.Id);

            SelectedVaultNameLabel.Text = vault.Name;

            VaultSelectionPanel.Visibility = Visibility.Collapsed;
            CreateVaultForm.Visibility = Visibility.Collapsed;
            UnlockForm.Visibility = Visibility.Visible;
            LoginStatusMessage.Text = "";
            UnlockPassword.Password = "";

            CheckVaultState();

            // The lockout is persisted per vault, so a pending one has to be shown
            // again here rather than silently waiting for the next failed attempt.
            if (_storageService.IsLockedOut(out int lockoutRemaining))
            {
                StartLockout(lockoutRemaining);
            }
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
                    try
                    {
                        // If this is the vault currently open, its secrets must not
                        // outlive the files being erased.
                        if (_selectedVault != null && _selectedVault.Id == vaultId)
                        {
                            CloseVaultSession();
                            _vaultPaths.ClearSelection();
                            _selectedVault = null;
                            _storageService.Dispose();
                            _storageService = new StorageService(_vaultPaths.ActivePath);
                            _viewModel.UpdateStorageService(_storageService);
                        }

                        if (Directory.Exists(vault.Path))
                        {
                            Directory.Delete(vault.Path, true);
                        }

                        _vaultManager.DeleteVault(vaultId);
                        RefreshVaultList();
                    }
                    catch
                    {
                        ShowDialog(loc["DeleteVault"], loc["ImportFailed"]);
                    }
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
        var loc = _localization;

        // SecurePassword rather than Password: a .NET string is immutable and cannot
        // be cleared, so a master password that becomes one stays in the heap.
        using var securePassword = CreateMasterPassword.SecurePassword;
        using var secureConfirm = ConfirmMasterPassword.SecurePassword;
        
        if (string.IsNullOrEmpty(vaultName))
        {
            LoginStatusMessage.Text = loc["VaultNameRequired"];
            return;
        }

        // The name becomes a directory under the vaults root, so it has to be a
        // usable Windows folder name and must not escape that root.
        if (!VaultNameValidator.IsValid(vaultName))
        {
            LoginStatusMessage.Text = loc["InvalidVaultName"];
            return;
        }

        var existingVaults = _vaultManager.GetAllVaults();
        if (existingVaults.Any(v => v.Name.Equals(vaultName, StringComparison.OrdinalIgnoreCase)))
        {
            LoginStatusMessage.Text = loc["VaultNameExists"];
            return;
        }
        
        if (securePassword.Length == 0)
        {
            LoginStatusMessage.Text = loc["PasswordRequired"];
            return;
        }

        if (securePassword.Length < 8)
        {
            LoginStatusMessage.Text = loc["PasswordTooShort"];
            return;
        }

        var vaultPath = Path.Combine(_vaultPaths.RootPath, vaultName);

        // Scratch buffers we own and wipe; the converter never builds a managed
        // string, and the exact length comes back from the write.
        var passwordBytes = new byte[SecureStringConverter.GetMaxByteCount(securePassword)];
        var confirmBytes = new byte[SecureStringConverter.GetMaxByteCount(secureConfirm)];

        try
        {
            var passwordLength = SecureStringConverter.WriteUtf8Bytes(securePassword, passwordBytes);
            var confirmLength = SecureStringConverter.WriteUtf8Bytes(secureConfirm, confirmBytes);

            if (!CryptographicOperations.FixedTimeEquals(
                    passwordBytes.AsSpan(0, passwordLength),
                    confirmBytes.AsSpan(0, confirmLength)))
            {
                LoginStatusMessage.Text = loc["PasswordsMismatch"];
                return;
            }

            var vault = _vaultManager.CreateVault(vaultName, vaultPath);

            _storageService.Dispose();
            _storageService = new StorageService(vaultPath);
            _viewModel.UpdateStorageService(_storageService);
            _vaultPaths.SelectVault(vaultPath);
            _selectedVault = vault;

            _storageService.CreateVault(passwordBytes.AsSpan(0, passwordLength));
        }
        catch (Exception)
        {
            LoginStatusMessage.Text = loc["VaultCreateFailed"];
            return;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(confirmBytes);
        }

        CreateMasterPassword.Password = "";
        ConfirmMasterPassword.Password = "";
        
        _viewModel.Credentials.Clear();
        _viewModel.FilterCredentials();
        ShowMainApp();
    }

    private void Unlock_Click(object sender, RoutedEventArgs e)
    {
        using var securePassword = UnlockPassword.SecurePassword;

        if (securePassword.Length == 0)
        {
            LoginStatusMessage.Text = _localization["EnterMasterPassword"];
            return;
        }

        // A scratch buffer we own and wipe; PasswordBox.Password would hand back an
        // immutable string that cannot be cleared at all.
        var passwordBytes = new byte[SecureStringConverter.GetMaxByteCount(securePassword)];

        try
        {
            var passwordLength = SecureStringConverter.WriteUtf8Bytes(securePassword, passwordBytes);

            // VerifyPassword derives the key and opens the vault in one pass. It also
            // validates the stored vault version, so it can throw and belongs inside
            // this try rather than ahead of it.
            var (success, errorMessage, remainingSeconds) = _storageService.VerifyPassword(passwordBytes.AsSpan(0, passwordLength));
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

            var credentials = _storageService.LoadVault();

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
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
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

    private string FormatPasswordMetrics(string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return "";
        }

        var result = _passwordGenerator.AnalyzeStrength(password);
        var crackTime = string.Format(_localization[result.CrackTime.UnitKey], result.CrackTime.Amount);

        return string.Format(_localization["PasswordMetrics"], result.EntropyBits, crackTime);
    }

    private void UpdateStrengthIndicator(string password)
    {
        if (StrengthFill == null || StrengthLabel == null)
            return;

        var result = _passwordGenerator.AnalyzeStrength(password);

        // Buckets come from PasswordStrengthPresenter so the meter and the analyzer
        // cannot drift apart again.
        var presentation = PasswordStrengthPresenter.Describe(result.Score);
        var fillPercent = presentation.FillPercent;
        var color = StrengthColor(presentation.LocalizationKey);

        StrengthLabel.Text = _localization[presentation.LocalizationKey];
        StrengthFill.Background = new System.Windows.Media.SolidColorBrush(color);
        StrengthLabel.Foreground = new System.Windows.Media.SolidColorBrush(color);
        
        StrengthLabel.Measure(new System.Windows.Size(double.PositiveInfinity, double.PositiveInfinity));
        var textWidth = StrengthLabel.DesiredSize.Width;
        var availableWidth = Math.Max(0, StrengthGrid.ActualWidth - textWidth - 4);
        StrengthFill.Width = availableWidth * fillPercent / 100.0;

        if (PasswordMetrics != null)
        {
            PasswordMetrics.Text = FormatPasswordMetrics(password);
        }
    }

    private static System.Windows.Media.Color StrengthColor(string localizationKey) => localizationKey switch
    {
        "VeryStrong" => System.Windows.Media.Color.FromRgb(34, 197, 94),
        "Strong" => System.Windows.Media.Color.FromRgb(132, 204, 22),
        "Good" => System.Windows.Media.Color.FromRgb(252, 186, 3),
        "Fair" => System.Windows.Media.Color.FromRgb(255, 140, 0),
        _ => System.Windows.Media.Color.FromRgb(220, 38, 52)
    };

    private void StrengthGrid_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (_passwordGenerator != null && GeneratedPassword != null)
        {
            var result = _passwordGenerator.AnalyzeStrength(GeneratedPassword.Text ?? "");
            var fillPercent = PasswordStrengthPresenter.Describe(result.Score).FillPercent;
            
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

    // Clipboard calls fail whenever another process holds the clipboard open, which
    // clipboard managers and RDP sessions do routinely - that used to crash the app.
    private void CopyToClipboard(string value, string successMessageKey)
    {
        if (SecureClipboard.TrySetText(value))
        {
            StatusMessage.Text = _localization[successMessageKey];
            StartClipboardClearTimer();
        }
        else
        {
            StatusMessage.Text = _localization["ClipboardUnavailable"];
        }
    }

    private void CopyUsername_Click(object sender, RoutedEventArgs e)
    {
        var credential = _viewModel.SelectedCredential;
        if (credential != null)
        {
            var username = !string.IsNullOrEmpty(credential.Username) ? credential.Username : credential.Email;
            if (!string.IsNullOrEmpty(username))
            {
                CopyToClipboard(username, "UsernameCopied");
            }
        }
    }

    private void CopyEmail_Click(object sender, RoutedEventArgs e)
    {
        var credential = _viewModel.SelectedCredential;
        if (credential != null && !string.IsNullOrEmpty(credential.Email))
        {
            CopyToClipboard(credential.Email, "EmailCopied");
        }
    }

    private void CopyWebsite_Click(object sender, RoutedEventArgs e)
    {
        var credential = _viewModel.SelectedCredential;
        if (credential != null && !string.IsNullOrEmpty(credential.Website))
        {
            CopyToClipboard(credential.Website, "WebsiteCopied");
        }
    }

    private void CopyPassword_Click(object sender, RoutedEventArgs e)
    {
        var credential = _viewModel.SelectedCredential;
        if (credential != null)
        {
            CopyToClipboard(credential.Password, "PasswordCopied");
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
            CredentialPasswordMetrics.Text = FormatPasswordMetrics(credential.Password);
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
        ScreenCaptureProtectionCheckBox.IsChecked = _screenCaptureProtectionEnabled;
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
        if (ApplyPathChanges())
        {
            SavePathSettings();
        }

        // Settings is an overlay, not a logout. Always falling through to the vault
        // list looked like a lock while the vault stayed unlocked and the master key
        // stayed in memory, so return to whichever screen opened settings.
        if (_previousScreen == MainApp && _isVaultUnlocked)
        {
            SettingsPanel.Visibility = Visibility.Collapsed;
            LoginScreen.Visibility = Visibility.Collapsed;
            MainApp.Visibility = Visibility.Visible;
            ResetAutoLockTimer();
        }
        else
        {
            ShowVaultSelection();
        }

        _previousScreen = null;
    }

    private void VaultPathBrowseBtn_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog();
        if (dialog.ShowDialog() == true)
        {
            VaultPathTextBox.Text = dialog.FolderName;
            if (ApplyPathChanges())
            {
                SavePathSettings();
            }
        }
    }

    private void VaultPathResetBtn_Click(object sender, RoutedEventArgs e)
    {
        var defaultPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CipherVault");
        VaultPathTextBox.Text = defaultPath;
        if (ApplyPathChanges())
        {
            SavePathSettings();
        }
    }

    private Action? _dialogConfirmAction;
    private Action? _dialogCancelAction;

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

    private void ShowConfirmDialog(string title, string message, Action onConfirm, Action? onCancel = null)
    {
        DialogTitle.Text = title;
        DialogMessage.Text = message;
        DialogCancelBtn.Visibility = Visibility.Visible;
        DialogCancelBtn.Content = _localization["Cancel"];
        DialogOkBtn.Content = _localization["Confirm"];
        DialogOverlay.Visibility = Visibility.Visible;
        DialogOverlay.KeyDown += DialogOverlay_KeyDown;
        _dialogConfirmAction = onConfirm;
        _dialogCancelAction = onCancel;
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
        _dialogCancelAction = null;
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
        _dialogCancelAction?.Invoke();
        _dialogCancelAction = null;
        _exportAction = null;
    }

    private void ScreenCaptureProtectionCheckBox_Changed(object sender, RoutedEventArgs e)
    {
        var enabled = ScreenCaptureProtectionCheckBox.IsChecked == true;

        if (enabled == _screenCaptureProtectionEnabled)
        {
            // Fired by loading the setting into the UI, not by the user.
            return;
        }

        if (enabled)
        {
            ApplyScreenCaptureProtection(true);
            return;
        }

        // Turning it off is a downgrade, so it is confirmed; turning it on is not.
        var loc = _localization;
        ShowConfirmDialog(
            loc["ScreenCaptureProtectionOffTitle"],
            loc["ScreenCaptureProtectionOffWarning"],
            () => ApplyScreenCaptureProtection(false),
            () => ScreenCaptureProtectionCheckBox.IsChecked = true);
    }

    private void ApplyScreenCaptureProtection(bool enabled)
    {
        _screenCaptureProtectionEnabled = enabled;
        _settings.SetBool(AppSettingsStore.ScreenCaptureProtectionKey, enabled);

        // Reapplies to every window the app owns. The periodic sweep reads the same
        // flag, so it will not quietly restore protection a moment after this.
        ProtectAllAppWindows();
    }

    private void LoggingEnabledCheckBox_Changed(object sender, RoutedEventArgs e)
    {
        var enabled = LoggingEnabledCheckBox.IsChecked == true;
        AuditService.LoggingEnabled = enabled;
        _settings.SetBool(AppSettingsStore.LoggingEnabledKey, enabled);
    }

    private void OpenLogsFolderBtn_Click(object sender, RoutedEventArgs e)
    {
        // Ask the audit service where it actually writes instead of guessing, and let
        // the shell open the folder so a username containing a space still resolves.
        var logsPath = AuditService.Instance?.LogFolderPath
            ?? Path.Combine(GetConfigDirectory(), "Logs");

        try
        {
            Directory.CreateDirectory(logsPath);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = logsPath,
                UseShellExecute = true
            });
        }
        catch
        {
        }
    }

    private void DeleteCurrentVaultBtn_Click(object sender, RoutedEventArgs e)
    {
        var loc = _localization;

        // Refuse when nothing is selected, or when the selection is the vaults root -
        // deleting the root takes every vault the user has with it.
        if (!_vaultPaths.CanDeleteCurrentVault)
        {
            ShowDialog(loc["DeleteCurrentVault"], loc["NoVaultSelectedToDelete"]);
            return;
        }

        var vaultPath = _vaultPaths.DeleteTargetPath;

        ShowConfirmDialog(loc["DeleteCurrentVault"], loc["DeleteVaultWarning"], () =>
        {
            try
            {
                // The master key and decrypted credentials must not outlive the files.
                CloseVaultSession();

                if (Directory.Exists(vaultPath))
                {
                    Directory.Delete(vaultPath, true);
                }

                if (_selectedVault != null)
                {
                    _vaultManager.DeleteVault(_selectedVault.Id);
                    _selectedVault = null;
                }

                _vaultPaths.ClearSelection();

                _storageService.Dispose();
                _storageService = new StorageService(_vaultPaths.ActivePath);
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
        // Extracted into a local so the finally below can always reach it: every early
        // return and every exception used to leave a decryptable copy of someone's
        // vault sitting in %TEMP%.
        string tempDir = "";

        try
        {
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
            if (!VaultNameValidator.IsValid(vaultName))
            {
                ShowDialog(loc["ImportVault"], loc["InvalidVaultName"]);
                return;
            }

            var existingVaults = _vaultManager.GetAllVaults();
            var baseName = vaultName;
            var counter = 1;
            while (existingVaults.Any(v => v.Name.Equals(vaultName, StringComparison.OrdinalIgnoreCase)))
            {
                vaultName = $"{baseName} ({counter})";
                counter++;
            }

            var vaultPath = Path.Combine(_vaultPaths.RootPath, vaultName);
            Directory.CreateDirectory(vaultPath);

            File.Copy(vaultDatPath, Path.Combine(vaultPath, "vault.dat"), true);
            File.Copy(configJsonPath, Path.Combine(vaultPath, "config.json"), true);

            _vaultManager.CreateVault(vaultName, vaultPath);

            RefreshVaultList();
            ShowDialog(loc["ImportVault"], loc["ImportSuccess"]);
        }
        catch
        {
            ShowDialog(loc["ImportVault"], loc["ImportFailed"]);
        }
        finally
        {
            if (!string.IsNullOrEmpty(tempDir) && Directory.Exists(tempDir))
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }
    }

    private void SavePathSettings()
    {
        _settings.SetString(AppSettingsStore.VaultPathKey, VaultPathTextBox.Text);
    }

    private static string GetDefaultVaultRoot()
    {
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CipherVault");
    }

    private static string GetConfigDirectory()
    {
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CipherVault");
    }

    // Reads the configured vaults ROOT. It must not touch the selected vault:
    // opening Settings used to retarget the current vault at the root, which made
    // "delete this vault" delete every vault instead.
    private void LoadPathSettings()
    {
        var rootPath = _settings.GetString(AppSettingsStore.VaultPathKey) ?? GetDefaultVaultRoot();

        _vaultPaths.SetRoot(rootPath);
        VaultPathTextBox.Text = rootPath;
    }

    /// <summary>
    /// Applies the path typed into settings. Returns false when the change was
    /// refused, so the caller does not persist a path the app just rejected.
    /// </summary>
    private bool ApplyPathChanges()
    {
        var newVaultPath = VaultPathTextBox.Text;

        if (newVaultPath != _vaultPaths.RootPath)
        {
            if (_isVaultUnlocked)
            {
                var loc = _localization;
                ShowDialog(loc["VaultOpen"], loc["LockVaultBeforePathChange"]);
                LoadPathSettings();
                return false;
            }

            _storageService.Dispose();
            _vaultPaths.SetRoot(newVaultPath);
            _vaultPaths.ClearSelection();
            _selectedVault = null;
            _storageService = new StorageService(_vaultPaths.ActivePath);
            _viewModel.UpdateStorageService(_storageService);

            CheckVaultState();

            if (!_storageService.VaultExists())
            {
                var loc = _localization;
                ShowDialog(loc["Warning"], loc["NoVaultAtPath"]);
            }
        }

        return true;
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
