# CipherVault Fluent UI Redesign — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild CipherVault's interface on the WPF UI design system with smooth animations, vector icons, a screen-capture toggle, and a visible entropy/crack-time readout — without weakening any security property.

**Architecture:** WPF stays. The `WPF-UI` package supplies theme resources, Fluent controls, window chrome and the Fluent System Icons set. All existing screens keep their structure and their `x:Name` values; only styles, templates, icons and the window shell change. The three master-password fields deliberately stay on the native WPF `PasswordBox`.

**Tech Stack:** .NET 8 (`net8.0-windows10.0.26100.0`), WPF, `WPF-UI` 4.3.0, xUnit.

**Spec:** `docs/superpowers/specs/2026-09-08-fluent-ui-redesign-design.md`

## Global Constraints

- Framework stays WPF. Package: `WPF-UI` version `4.3.0` (has `lib/net8.0-windows7.0`).
- Target framework stays `net8.0-windows10.0.26100.0`. Do not change it.
- `CreateMasterPassword`, `ConfirmMasterPassword`, `UnlockPassword` MUST remain `System.Windows.Controls.PasswordBox`. Never `ui:PasswordBox` — that type has no `SecurePassword`.
- Every existing `x:Name` is preserved verbatim. The only exception is the custom title-bar area, which moves into `ui:TitleBar`.
- Dark theme only. No light theme, no theme switcher.
- Animation durations: screen transitions 180 ms; dialog overlay 120 ms; detail cross-fade 120 ms; list stagger 25 ms per item capped at 10 items; strength bar 250 ms; panel expand 200 ms. Easing: `CubicEase` with `EasingMode="EaseOut"`.
- Icon sizes: 20 for inline/in-field icons, 24 for panel buttons. Icons inherit `Foreground`; never hardcode icon colour.
- Screen-capture protection defaults to ON. Settings key: `screenCaptureProtection`.
- **The test project is git-ignored and is not in the solution.** Run tests with `dotnet test CipherVault.Tests/CipherVault.Tests.csproj`. Build with `dotnet build CipherVault.sln`. **Never `git add CipherVault.Tests`** — commit production code only.
- Every task ends with `dotnet build CipherVault.sln --no-incremental` reporting `Предупреждений: 0` and `Ошибок: 0`.
- Work on branch `work_test`. Commit and push there; no PRs.

---

### Task 1: Guard the master-password fields before any markup is touched

This task comes first on purpose. It is the tripwire that protects every later markup change from silently reintroducing a managed plaintext password.

**Files:**
- Test: `CipherVault.Tests/MasterPasswordFieldTests.cs` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: nothing consumed by later tasks. It constrains them.

- [ ] **Step 1: Write the failing test**

Create `CipherVault.Tests/MasterPasswordFieldTests.cs`:

```csharp
using System.IO;
using System.Xml.Linq;
using Xunit;

namespace CipherVault.Tests;

public class MasterPasswordFieldTests
{
    private static readonly XNamespace Wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
    private static readonly XNamespace Xaml = "http://schemas.microsoft.com/winfx/2006/xaml";

    private static XDocument LoadMainWindowMarkup()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "MainWindow.xaml")))
        {
            directory = directory.Parent;
        }

        Assert.True(directory != null, "MainWindow.xaml was not found above the test output directory");
        return XDocument.Load(Path.Combine(directory!.FullName, "MainWindow.xaml"));
    }

    [Theory]
    [InlineData("CreateMasterPassword")]
    [InlineData("ConfirmMasterPassword")]
    [InlineData("UnlockPassword")]
    public void MasterPasswordFieldIsTheNativeWpfPasswordBox(string elementName)
    {
        var element = LoadMainWindowMarkup()
            .Descendants()
            .SingleOrDefault(e => (string?)e.Attribute(Xaml + "Name") == elementName);

        Assert.True(element != null, $"no element named {elementName} in MainWindow.xaml");

        // A library PasswordBox (Wpf.Ui's, for one) exposes only a string Password.
        // The master password must never become an immutable managed string.
        Assert.Equal(Wpf + "PasswordBox", element!.Name);
    }

    [Fact]
    public void NoLibraryPasswordBoxIsUsedForAnyMasterPasswordField()
    {
        var suspicious = LoadMainWindowMarkup()
            .Descendants()
            .Where(e => e.Name.LocalName == "PasswordBox" && e.Name.Namespace != Wpf)
            .Select(e => (string?)e.Attribute(Xaml + "Name"))
            .ToList();

        Assert.Empty(suspicious);
    }
}
```

- [ ] **Step 2: Run the test and confirm it passes today**

Run: `dotnet test CipherVault.Tests/CipherVault.Tests.csproj --filter "FullyQualifiedName~MasterPasswordFieldTests"`
Expected: PASS, 4 tests. This test is a guard, not a red-green cycle — it must be green now and stay green. If it fails now, the markup already regressed and that must be fixed before anything else.

- [ ] **Step 3: Deliberately verify the guard bites**

Temporarily change `UnlockPassword`'s element in `MainWindow.xaml` from `<PasswordBox` to `<ui:PasswordBox` (the `ui` prefix does not exist yet, so also add `xmlns:ui="http://schemas.lepo.co/wpfui/2022/xaml"` to the `Window` tag for this check only).

Run: `dotnet test CipherVault.Tests/CipherVault.Tests.csproj --filter "FullyQualifiedName~MasterPasswordFieldTests"`
Expected: FAIL on `MasterPasswordFieldIsTheNativeWpfPasswordBox` and `NoLibraryPasswordBoxIsUsedForAnyMasterPasswordField`.

Then revert both edits with `git checkout -- MainWindow.xaml` and re-run to confirm PASS again. A guard nobody proved can fail is not a guard.

- [ ] **Step 4: Commit**

The test file is git-ignored, so this task has nothing to commit. Confirm that:

```bash
git status --short
```

Expected: no changes listed for `MainWindow.xaml` and nothing under `CipherVault.Tests/`. Move to Task 2.

---

### Task 2: Add the WPF UI package and theme resources

**Files:**
- Modify: `CipherVault.csproj` (the `PackageReference` group)
- Modify: `App.xaml` (`Application.Resources`)

**Interfaces:**
- Consumes: nothing.
- Produces: the `ui` XAML namespace `http://schemas.lepo.co/wpfui/2022/xaml` and WPF UI theme resources available application-wide. Every later markup task relies on this.

- [ ] **Step 1: Add the package**

```bash
dotnet add CipherVault.csproj package WPF-UI --version 4.3.0
```

- [ ] **Step 2: Merge the library dictionaries into App.xaml**

In `App.xaml`, `Application.Resources` currently opens as:

```xml
    <Application.Resources>
        <ResourceDictionary>
            <!-- Colors -->
            <Color x:Key="PrimaryDark">#0D1117</Color>
```

Add the `ui` namespace to the `Application` element and merge the library dictionaries as the FIRST entries, before the existing colours. Library dictionaries must come first so our own keys win where they overlap:

```xml
<Application x:Class="CipherVault.App"
             xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
             xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
             xmlns:ui="http://schemas.lepo.co/wpfui/2022/xaml"
             xmlns:local="clr-namespace:CipherVault"
             StartupUri="MainWindow.xaml">
    <Application.Resources>
        <ResourceDictionary>
            <ResourceDictionary.MergedDictionaries>
                <ui:ThemesDictionary Theme="Dark" />
                <ui:ControlsDictionary />
            </ResourceDictionary.MergedDictionaries>

            <!-- Colors -->
            <Color x:Key="PrimaryDark">#0D1117</Color>
```

Leave every existing colour, brush and style exactly as it is. This step only makes the library available; restyling happens in Task 8.

- [ ] **Step 3: Build and run**

```bash
dotnet build CipherVault.sln --no-incremental
```

Expected: `Предупреждений: 0`, `Ошибок: 0`.

Launch the app and confirm it still looks exactly as before and every screen still opens:

```bash
./bin/Debug/net8.0-windows10.0.26100.0/win-x64/CipherVault.exe
```

Close it. If any control changed appearance, the library's implicit styles are leaking — note which control and fix by giving that control an explicit `Style` referencing the existing key.

- [ ] **Step 4: Run the full suite**

Run: `dotnet test CipherVault.Tests/CipherVault.Tests.csproj`
Expected: PASS, all tests (134 plus the 4 from Task 1 = 138).

- [ ] **Step 5: Commit**

```bash
git add CipherVault.csproj App.xaml
git commit -m "Add WPF UI theme and control dictionaries

Package only, plus the merged dictionaries. No screen changes yet: this
keeps the dependency addition separately reviewable from the restyle."
```

---

### Task 3: Move the window to FluentWindow with a real title bar

**Files:**
- Modify: `MainWindow.xaml` (the `Window` element, lines 1-19; the custom title bar markup; the four root grids' `Margin`)
- Modify: `MainWindow.xaml.cs` (remove `Window_MouseLeftButtonDown` and `Window_StateChanged`)

**Interfaces:**
- Consumes: the `ui` namespace from Task 2.
- Produces: a resizable window whose chrome is `ui:TitleBar`. `SettingsBtn_Click` still exists and is still wired.

- [ ] **Step 1: Change the window type**

In `MainWindow.xaml`, replace the opening `Window` element:

```xml
<ui:FluentWindow x:Class="CipherVault.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:ui="http://schemas.lepo.co/wpfui/2022/xaml"
        xmlns:local="clr-namespace:CipherVault"
        xmlns:vm="clr-namespace:CipherVault.ViewModels"
        xmlns:converters="clr-namespace:CipherVault.Converters"
        mc:Ignorable="d"
        Title="CipherVault - Password Manager"
        Height="800" Width="1100"
        MinHeight="600" MinWidth="900"
        WindowStartupLocation="CenterScreen"
        WindowBackdropType="Mica"
        ExtendsContentIntoTitleBar="True"
        Loaded="MainWindow_Loaded">
```

Removed on purpose: `WindowStyle="None"`, `ResizeMode="NoResize"`, `Background`, `MouseLeftButtonDown`, `StateChanged`. Change the closing tag at the end of the file from `</Window>` to `</ui:FluentWindow>`.

**Do not add `SourceInitialized` here.** `MainWindow_SourceInitialized` exists and is already subscribed from the constructor in `MainWindow.xaml.cs`; adding the attribute would subscribe it twice and apply the capture affinity twice. Confirm with `grep -n "SourceInitialized" MainWindow.xaml.cs` before touching it.

- [ ] **Step 2: Change the code-behind base class**

In `MainWindow.xaml.cs`, change the class declaration:

```csharp
public partial class MainWindow : Wpf.Ui.Controls.FluentWindow
```

Delete the `Window_MouseLeftButtonDown` and `Window_StateChanged` methods entirely — `ui:TitleBar` provides dragging, maximise and restore.

- [ ] **Step 3: Replace the custom title bar with ui:TitleBar**

The existing custom bar is the markup that the four root grids sit below (they carry `Margin="0,40,0,0"`). Put a `ui:TitleBar` as the first child of the root `Grid` and delete the hand-rolled bar, keeping the settings button:

```xml
<ui:TitleBar Grid.Row="0" Title="CipherVault" ShowMaximize="True" ShowMinimize="True">
    <ui:TitleBar.Header>
        <StackPanel Orientation="Horizontal" Margin="12,0,0,0">
            <ui:SymbolIcon Symbol="ShieldKeyhole24" FontSize="20" Margin="0,0,8,0"/>
            <TextBlock Text="CipherVault" VerticalAlignment="Center" FontWeight="SemiBold"/>
        </StackPanel>
    </ui:TitleBar.Header>
</ui:TitleBar>
```

Restructure the root `Grid` to two rows: row 0 is the title bar, row 1 holds the four screens. Give `SettingsPanel`, `LoginScreen`, `MainApp` and `DialogOverlay` `Grid.Row="1"` and delete their `Margin="0,40,0,0"`.

The title-bar settings button (the one at former line 214 with `Click="SettingsBtn_Click"`) moves into the `ui:TitleBar.Header` StackPanel as:

```xml
<ui:Button Icon="{ui:SymbolIcon Settings24}" Appearance="Transparent"
           ToolTip="Settings" Click="SettingsBtn_Click" Margin="8,0,0,0"/>
```

- [ ] **Step 4: Build**

```bash
dotnet build CipherVault.sln --no-incremental
```

Expected: `Ошибок: 0`. A `CS0103` about a missing handler means a `Click`/`MouseDown` attribute in the markup still points at a method you deleted — remove that attribute.

- [ ] **Step 5: Verify the window and, critically, screen-capture protection**

Launch the app. Confirm: the window can be resized by dragging its edge; maximise and restore work; Snap Layouts appear when hovering maximise; the settings gear still opens settings.

Then confirm capture protection survived the chrome change — this is the step that must not be skipped, because `SetWindowDisplayAffinity` and the Mica backdrop both work through DWM:

With the app open, press `Win+Shift+S`, select the CipherVault window area, and paste into Paint. Expected: the CipherVault window area is **black**. If it is not, `PreventScreenCapture` is no longer reaching the right HWND — check that `MainWindow_SourceInitialized` still fires and that `WindowInteropHelper(this).Handle` is non-zero at that point.

- [ ] **Step 6: Run the full suite**

Run: `dotnet test CipherVault.Tests/CipherVault.Tests.csproj`
Expected: PASS, 138 tests. The Task 1 guard must still be green.

- [ ] **Step 7: Commit**

```bash
git add MainWindow.xaml MainWindow.xaml.cs
git commit -m "Replace the fixed-size custom chrome with FluentWindow

WindowStyle=None plus ResizeMode=NoResize meant the window could not be
resized at all and reimplemented dragging by hand. ui:TitleBar restores
resizing, maximise, Snap Layouts and correct DPI handling, so the manual
drag and state handlers are gone.

Screen-capture protection verified still black in a Win+Shift+S capture."
```

---

### Task 4: A testable rule for the screen-capture affinity value

**Files:**
- Create: `Services/ScreenCaptureAffinity.cs`
- Test: `CipherVault.Tests/ScreenCaptureAffinityTests.cs`

**Interfaces:**
- Consumes: nothing.
- Produces: `ScreenCaptureAffinity.For(bool protectionEnabled, bool excludeFromCaptureSupported) -> uint`, plus the constants `None`, `Monitor`, `ExcludeFromCapture`. Task 5 calls this.

- [ ] **Step 1: Write the failing test**

Create `CipherVault.Tests/ScreenCaptureAffinityTests.cs`:

```csharp
using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class ScreenCaptureAffinityTests
{
    [Fact]
    public void ProtectionOnModernWindowsExcludesTheWindowFromCapture()
    {
        Assert.Equal(ScreenCaptureAffinity.ExcludeFromCapture,
            ScreenCaptureAffinity.For(protectionEnabled: true, excludeFromCaptureSupported: true));
    }

    [Fact]
    public void ProtectionOnOlderWindowsFallsBackToMonitorAffinity()
    {
        Assert.Equal(ScreenCaptureAffinity.Monitor,
            ScreenCaptureAffinity.For(protectionEnabled: true, excludeFromCaptureSupported: false));
    }

    [Fact]
    public void ProtectionOffMeansNoAffinityAtAll()
    {
        Assert.Equal(ScreenCaptureAffinity.None,
            ScreenCaptureAffinity.For(protectionEnabled: false, excludeFromCaptureSupported: true));
        Assert.Equal(ScreenCaptureAffinity.None,
            ScreenCaptureAffinity.For(protectionEnabled: false, excludeFromCaptureSupported: false));
    }

    [Fact]
    public void TheConstantsMatchTheWin32Values()
    {
        Assert.Equal(0x00000000u, ScreenCaptureAffinity.None);
        Assert.Equal(0x00000001u, ScreenCaptureAffinity.Monitor);
        Assert.Equal(0x00000011u, ScreenCaptureAffinity.ExcludeFromCapture);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `dotnet test CipherVault.Tests/CipherVault.Tests.csproj --filter "FullyQualifiedName~ScreenCaptureAffinityTests"`
Expected: FAIL to compile with `CS0103: Имя "ScreenCaptureAffinity" не существует в текущем контексте`.

- [ ] **Step 3: Write the minimal implementation**

Create `Services/ScreenCaptureAffinity.cs`:

```csharp
namespace CipherVault.Services;

/// <summary>
/// Which WDA_* value SetWindowDisplayAffinity should be given.
///
/// Kept apart from the P/Invoke so the decision itself is testable: the call
/// cannot be exercised in a test, but choosing the wrong value silently leaves
/// the vault visible to screenshots.
/// </summary>
public static class ScreenCaptureAffinity
{
    public const uint None = 0x00000000;
    public const uint Monitor = 0x00000001;
    public const uint ExcludeFromCapture = 0x00000011;

    public static uint For(bool protectionEnabled, bool excludeFromCaptureSupported)
    {
        if (!protectionEnabled)
        {
            return None;
        }

        // WDA_EXCLUDEFROMCAPTURE needs Windows 10 2004 (build 19041). Older builds
        // get WDA_MONITOR: capture APIs still see black, only DWM thumbnails leak.
        return excludeFromCaptureSupported ? ExcludeFromCapture : Monitor;
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `dotnet test CipherVault.Tests/CipherVault.Tests.csproj --filter "FullyQualifiedName~ScreenCaptureAffinityTests"`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add Services/ScreenCaptureAffinity.cs
git commit -m "Extract the screen-capture affinity decision behind a testable rule"
```

---

### Task 5: A settings toggle for screen-capture protection

**Files:**
- Modify: `Services/AppSettingsStore.cs` (add the key constant)
- Modify: `MainWindow.xaml` (`SettingsPanel`, beside the logging row at former lines 120-131)
- Modify: `MainWindow.xaml.cs` (`PreventScreenCapture`, `ProtectAllAppWindows`, `_captureAffinity`, new handler)
- Modify: `Services/LocalizationService.cs` (four new keys, both languages)
- Test: `CipherVault.Tests/AppSettingsStoreTests.cs` (add one test)

**Interfaces:**
- Consumes: `ScreenCaptureAffinity.For` from Task 4; `AppSettingsStore.GetBool`/`SetBool`.
- Produces: `AppSettingsStore.ScreenCaptureProtectionKey`. Nothing later depends on it.

- [ ] **Step 1: Write the failing test**

Append to `CipherVault.Tests/AppSettingsStoreTests.cs`, inside the class:

```csharp
    [Fact]
    public void ScreenCaptureProtectionDefaultsToOnWhenNothingIsStored()
    {
        var store = new AppSettingsStore(_dir);

        Assert.True(store.GetBool(AppSettingsStore.ScreenCaptureProtectionKey, defaultValue: true));
    }

    [Fact]
    public void ScreenCaptureProtectionSurvivesBeingTurnedOff()
    {
        new AppSettingsStore(_dir).SetBool(AppSettingsStore.ScreenCaptureProtectionKey, false);

        Assert.False(new AppSettingsStore(_dir)
            .GetBool(AppSettingsStore.ScreenCaptureProtectionKey, defaultValue: true));
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `dotnet test CipherVault.Tests/CipherVault.Tests.csproj --filter "FullyQualifiedName~AppSettingsStoreTests"`
Expected: FAIL to compile — `AppSettingsStore` has no `ScreenCaptureProtectionKey`.

- [ ] **Step 3: Add the key**

In `Services/AppSettingsStore.cs`, beside the existing key constants:

```csharp
    public const string ScreenCaptureProtectionKey = "screenCaptureProtection";
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `dotnet test CipherVault.Tests/CipherVault.Tests.csproj --filter "FullyQualifiedName~AppSettingsStoreTests"`
Expected: PASS.

- [ ] **Step 5: Add the localization strings**

In `Services/LocalizationService.cs`, in the English dictionary beside the other settings entries:

```csharp
            ["ScreenCaptureProtection"] = "Block screenshots and screen sharing",
            ["ScreenCaptureProtectionOffTitle"] = "Turn off screenshot protection?",
            ["ScreenCaptureProtectionOffWarning"] = "With protection off, screenshots, screen sharing and screen recording will show your passwords. Turn it back on when you are done.",
```

And in the Russian dictionary:

```csharp
            ["ScreenCaptureProtection"] = "Блокировать снимки экрана и демонстрацию",
            ["ScreenCaptureProtectionOffTitle"] = "Отключить защиту от снимков экрана?",
            ["ScreenCaptureProtectionOffWarning"] = "С отключённой защитой снимки экрана, демонстрация экрана и запись видео покажут ваши пароли. Включите её обратно, когда закончите.",
```

- [ ] **Step 6: Add the toggle to the settings markup**

In `MainWindow.xaml`, directly below the logging row (the `Grid` holding `LoggingEnabledLabel` and `LoggingEnabledCheckBox`), add a row built the same way:

```xml
<Grid Margin="0,12,0,0">
    <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
    </Grid.ColumnDefinitions>
    <TextBlock Grid.Column="0" x:Name="ScreenCaptureProtectionLabel"
               Text="Block screenshots and screen sharing" FontSize="14"
               Foreground="{StaticResource TextPrimaryBrush}" VerticalAlignment="Center"/>
    <ui:ToggleSwitch Grid.Column="1" x:Name="ScreenCaptureProtectionToggle"
                     Checked="ScreenCaptureProtectionToggle_Changed"
                     Unchecked="ScreenCaptureProtectionToggle_Changed"/>
</Grid>
```

Find where `LoggingEnabledLabel.Text` is assigned from the localization dictionary in `MainWindow.xaml.cs` and assign `ScreenCaptureProtectionLabel.Text = _localization["ScreenCaptureProtection"];` beside it.

- [ ] **Step 7: Make the affinity respect the flag**

In `MainWindow.xaml.cs`, replace the static field and the two methods that use it.

Replace:

```csharp
    // Downgraded to WDA_MONITOR once if the OS is older than Windows 10 2004.
    private static uint _captureAffinity = WDA_EXCLUDEFROMCAPTURE;
```

with:

```csharp
    // Cleared once if the OS is older than Windows 10 2004 and cannot exclude from capture.
    private static bool _excludeFromCaptureSupported = true;
    private static bool _screenCaptureProtectionEnabled = true;

    private static uint CurrentCaptureAffinity =>
        ScreenCaptureAffinity.For(_screenCaptureProtectionEnabled, _excludeFromCaptureSupported);
```

Replace the body of `PreventScreenCapture`:

```csharp
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
```

In `ProtectAllAppWindows`, change the call to use the current value:

```csharp
                TrySetCaptureAffinity(hwndSource.Handle, CurrentCaptureAffinity);
```

Delete the now-unused `WDA_MONITOR` and `WDA_EXCLUDEFROMCAPTURE` constants; `ScreenCaptureAffinity` owns them.

**This is the step where the periodic sweep matters:** `ProtectAllAppWindows` is what `ScheduleCaptureProtectionSweep` invokes. Because it now reads `CurrentCaptureAffinity`, the sweep applies `WDA_NONE` when protection is off instead of silently restoring it a moment later.

- [ ] **Step 8: Load the setting at startup and handle the toggle**

In the `MainWindow` constructor, beside the existing `AuditService.LoggingEnabled = ...` line:

```csharp
        _screenCaptureProtectionEnabled =
            _settings.GetBool(AppSettingsStore.ScreenCaptureProtectionKey, defaultValue: true);
```

Where `LoggingEnabledCheckBox.IsChecked` is set from the loaded settings, add:

```csharp
        ScreenCaptureProtectionToggle.IsChecked = _screenCaptureProtectionEnabled;
```

Add the handler beside `LoggingEnabledCheckBox_Changed`:

```csharp
    private void ScreenCaptureProtectionToggle_Changed(object sender, RoutedEventArgs e)
    {
        var enabled = ScreenCaptureProtectionToggle.IsChecked == true;

        if (enabled)
        {
            ApplyScreenCaptureProtection(true);
            return;
        }

        // Turning it off is a downgrade, so it is confirmed. Turning it on is not.
        var loc = _localization;
        ShowConfirmDialog(loc["ScreenCaptureProtectionOffTitle"], loc["ScreenCaptureProtectionOffWarning"],
            () => ApplyScreenCaptureProtection(false),
            () => ScreenCaptureProtectionToggle.IsChecked = true);
    }

    private void ApplyScreenCaptureProtection(bool enabled)
    {
        _screenCaptureProtectionEnabled = enabled;
        _settings.SetBool(AppSettingsStore.ScreenCaptureProtectionKey, enabled);
        ProtectAllAppWindows();
    }
```

`ShowConfirmDialog` currently takes only a confirm callback. Add an optional cancel callback so declining restores the toggle instead of leaving it lying about the real state — find `ShowConfirmDialog` and `_dialogConfirmAction`, add a parallel `_dialogCancelAction`, invoke it on the cancel path, and give the new parameter a default of `null` so existing call sites keep compiling.

- [ ] **Step 9: Build and run the full suite**

```bash
dotnet build CipherVault.sln --no-incremental
dotnet test CipherVault.Tests/CipherVault.Tests.csproj
```

Expected: `Ошибок: 0`; all tests PASS (140).

- [ ] **Step 10: Verify by hand — the part no test can reach**

Launch the app and open Settings.

1. Protection on (default). `Win+Shift+S` over the window, paste in Paint → the window area is **black**.
2. Turn the toggle off → confirmation dialog appears with the warning text. Confirm.
3. Wait ten seconds so any pending sweep runs. `Win+Shift+S` again → the window is now **visible**. If it went black again, the sweep is not reading the flag.
4. Turn the toggle back on → no dialog. Capture again → **black**.
5. Turn it off, close the app, reopen → the toggle is still off and capture is still visible.
6. Switch the language to Russian and reopen Settings → the label and warning are Russian.

- [ ] **Step 11: Commit**

```bash
git add Services/AppSettingsStore.cs Services/LocalizationService.cs MainWindow.xaml MainWindow.xaml.cs
git commit -m "Let screenshot protection be turned off from settings

Defaults to on and persists. Turning it off asks for confirmation, because
it makes passwords visible to screenshots, screen sharing and recording;
turning it back on does not. The periodic sweep over app windows reads the
flag, otherwise it restored protection seconds after it was switched off."
```

---

### Task 6: Localize the crack-time wording

`FormatCrackTime` returns hardcoded English. Nothing displayed it until now, so nobody noticed; Task 7 puts it on screen.

**Files:**
- Modify: `Services/PasswordGenerator.cs` (`FormatCrackTime`, `AnalyzeStrength`, `PasswordStrengthResult`)
- Modify: `Services/LocalizationService.cs` (eight keys, both languages)
- Test: `CipherVault.Tests/CrackTimeDescriptionTests.cs` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `PasswordGenerator.DescribeCrackTime(double seconds) -> CrackTimeDescription`, where `public readonly record struct CrackTimeDescription(double Amount, string UnitKey)`. `PasswordStrengthResult.CrackTime` is of that type. `CrackTimeDisplay` and `FormatCrackTime` are removed. Task 7 consumes `CrackTime` and `EntropyBits`.

- [ ] **Step 1: Write the failing test**

Create `CipherVault.Tests/CrackTimeDescriptionTests.cs`:

```csharp
using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class CrackTimeDescriptionTests
{
    [Theory]
    [InlineData(0, "CrackTimeInstant")]
    [InlineData(0.5, "CrackTimeInstant")]
    [InlineData(1, "CrackTimeSeconds")]
    [InlineData(59, "CrackTimeSeconds")]
    [InlineData(60, "CrackTimeMinutes")]
    [InlineData(3599, "CrackTimeMinutes")]
    [InlineData(3600, "CrackTimeHours")]
    [InlineData(86399, "CrackTimeHours")]
    [InlineData(86400, "CrackTimeDays")]
    [InlineData(31535999, "CrackTimeDays")]
    [InlineData(31536000, "CrackTimeYears")]
    public void EachRangeGetsItsOwnUnitKey(double seconds, string expectedKey)
    {
        Assert.Equal(expectedKey, PasswordGenerator.DescribeCrackTime(seconds).UnitKey);
    }

    [Fact]
    public void ThousandsAndMillionsOfYearsGetTheirOwnUnits()
    {
        Assert.Equal("CrackTimeThousandYears",
            PasswordGenerator.DescribeCrackTime(31536000d * 5000).UnitKey);
        Assert.Equal("CrackTimeMillionYears",
            PasswordGenerator.DescribeCrackTime(31536000d * 5_000_000).UnitKey);
    }

    [Fact]
    public void TheAmountIsExpressedInTheUnitThatWasChosen()
    {
        var twoMinutes = PasswordGenerator.DescribeCrackTime(120);

        Assert.Equal("CrackTimeMinutes", twoMinutes.UnitKey);
        Assert.Equal(2, twoMinutes.Amount, precision: 6);
    }

    [Fact]
    public void InstantCarriesNoAmount()
    {
        Assert.Equal(0, PasswordGenerator.DescribeCrackTime(0.1).Amount);
    }

    [Fact]
    public void AnalyzeStrengthReportsTheDescription()
    {
        var result = new PasswordGenerator().AnalyzeStrength("aB3!dE7@fG1#hJ5%");

        Assert.False(string.IsNullOrEmpty(result.CrackTime.UnitKey));
    }

    [Fact]
    public void EveryUnitKeyExistsInBothLanguages()
    {
        var keys = new[]
        {
            "CrackTimeInstant", "CrackTimeSeconds", "CrackTimeMinutes", "CrackTimeHours",
            "CrackTimeDays", "CrackTimeYears", "CrackTimeThousandYears", "CrackTimeMillionYears"
        };

        var localization = LocalizationService.Instance;

        foreach (var language in new[] { "en", "ru" })
        {
            localization.SetLanguage(language);
            foreach (var key in keys)
            {
                Assert.False(string.IsNullOrWhiteSpace(localization[key]), $"{key} missing for {language}");
                Assert.NotEqual(key, localization[key]);
            }
        }
    }
}
```

Note: check how `LocalizationService` exposes its instance and language setter before running — if the member names differ, adapt this last test to the real API rather than changing the service.

- [ ] **Step 2: Run the test to verify it fails**

Run: `dotnet test CipherVault.Tests/CipherVault.Tests.csproj --filter "FullyQualifiedName~CrackTimeDescriptionTests"`
Expected: FAIL to compile — `DescribeCrackTime` does not exist.

- [ ] **Step 3: Implement the description**

In `Services/PasswordGenerator.cs`, delete `FormatCrackTime` entirely and add:

```csharp
    /// <summary>How long a crack takes, as a number plus the localization key for its unit.</summary>
    public readonly record struct CrackTimeDescription(double Amount, string UnitKey);

    private const double SecondsPerYear = 31536000d;

    public static CrackTimeDescription DescribeCrackTime(double seconds)
    {
        if (seconds < 1) return new CrackTimeDescription(0, "CrackTimeInstant");
        if (seconds < 60) return new CrackTimeDescription(seconds, "CrackTimeSeconds");
        if (seconds < 3600) return new CrackTimeDescription(seconds / 60, "CrackTimeMinutes");
        if (seconds < 86400) return new CrackTimeDescription(seconds / 3600, "CrackTimeHours");
        if (seconds < SecondsPerYear) return new CrackTimeDescription(seconds / 86400, "CrackTimeDays");
        if (seconds < SecondsPerYear * 1000) return new CrackTimeDescription(seconds / SecondsPerYear, "CrackTimeYears");
        if (seconds < SecondsPerYear * 1_000_000) return new CrackTimeDescription(seconds / SecondsPerYear / 1000, "CrackTimeThousandYears");
        return new CrackTimeDescription(seconds / SecondsPerYear / 1_000_000, "CrackTimeMillionYears");
    }
```

In `PasswordStrengthResult`, replace `public string CrackTimeDisplay { get; set; } = "";` with:

```csharp
    public PasswordGenerator.CrackTimeDescription CrackTime { get; set; }
```

In `AnalyzeStrength`, replace both assignments of `CrackTimeDisplay = FormatCrackTime(crackTimeSeconds)` (the early-return for an empty password and the final result) with `CrackTime = DescribeCrackTime(crackTimeSeconds)`. For the empty-password early return, `DescribeCrackTime(0)` gives the instant description.

- [ ] **Step 4: Add the eight localization keys**

English:

```csharp
            ["CrackTimeInstant"] = "instantly",
            ["CrackTimeSeconds"] = "{0:F0} seconds",
            ["CrackTimeMinutes"] = "{0:F0} minutes",
            ["CrackTimeHours"] = "{0:F0} hours",
            ["CrackTimeDays"] = "{0:F0} days",
            ["CrackTimeYears"] = "{0:F1} years",
            ["CrackTimeThousandYears"] = "{0:F0}K years",
            ["CrackTimeMillionYears"] = "{0:F0}M+ years",
```

Russian:

```csharp
            ["CrackTimeInstant"] = "мгновенно",
            ["CrackTimeSeconds"] = "{0:F0} с",
            ["CrackTimeMinutes"] = "{0:F0} мин",
            ["CrackTimeHours"] = "{0:F0} ч",
            ["CrackTimeDays"] = "{0:F0} дн.",
            ["CrackTimeYears"] = "{0:F1} лет",
            ["CrackTimeThousandYears"] = "{0:F0} тыс. лет",
            ["CrackTimeMillionYears"] = "{0:F0} млн+ лет",
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `dotnet test CipherVault.Tests/CipherVault.Tests.csproj --filter "FullyQualifiedName~CrackTimeDescriptionTests"`
Expected: PASS.

Then the whole suite: `dotnet test CipherVault.Tests/CipherVault.Tests.csproj` — expected PASS. If `PasswordGeneratorTests` fails on a missing `CrackTimeDisplay`, update that reference to `CrackTime`.

- [ ] **Step 6: Commit**

```bash
git add Services/PasswordGenerator.cs Services/LocalizationService.cs
git commit -m "Report crack time as a value plus a localized unit

FormatCrackTime returned hardcoded English - Instant, 3.2K years - which
nobody noticed while the figure was never displayed. The generator now
returns the amount and the localization key for its unit, and the
presentation layer does the joining."
```

---

### Task 7: Show entropy and crack time — in the generator and on a saved credential

Requested during execution: the readout belongs in two places, not one. The
generator answers "is the password I am about to use any good"; the credential
details pane answers "is the password I saved months ago still any good".

Adding it to the details pane exposes nothing new — `ShowCredentialDetails`
already reads `credential.Password` to render the masking dots, and
`AnalyzeStrength` neither stores nor transmits what it is given.

**Files:**
- Modify: `MainWindow.xaml` (`GeneratorPanel` under the strength meter; the credential details pane)
- Modify: `MainWindow.xaml.cs` (`UpdateStrengthIndicator`, `ShowCredentialDetails`)
- Modify: `Services/LocalizationService.cs` (one key, both languages)

**Interfaces:**
- Consumes: `PasswordStrengthResult.EntropyBits` and `.CrackTime` from Task 6; `PasswordStrengthPresenter.Describe` (already present).
- Produces: nothing.

- [ ] **Step 1: Add the template string**

English: `["PasswordMetrics"] = "{0} bits · cracked in {1}",`
Russian: `["PasswordMetrics"] = "{0} бит · взлом за {1}",`

- [ ] **Step 2: Add the readout to the markup**

Directly below the strength meter grid inside `GeneratorPanel`:

```xml
<TextBlock x:Name="PasswordMetrics" FontSize="12" Margin="0,6,0,0"
           Foreground="{StaticResource TextSecondaryBrush}"
           HorizontalAlignment="Left"/>
```

Pool size is deliberately not shown: it is an input to `length × log₂(poolSize)`, not a fact about the password.

- [ ] **Step 3: Fill it in**

At the end of `UpdateStrengthIndicator` in `MainWindow.xaml.cs`, after the existing fill-width code:

```csharp
        if (PasswordMetrics != null)
        {
            if (string.IsNullOrEmpty(password))
            {
                PasswordMetrics.Text = "";
            }
            else
            {
                var crackTime = string.Format(
                    _localization[result.CrackTime.UnitKey], result.CrackTime.Amount);

                PasswordMetrics.Text = string.Format(
                    _localization["PasswordMetrics"], result.EntropyBits, crackTime);
            }
        }
```

- [ ] **Step 4: Show the same readout on a saved credential**

Add a second `TextBlock` to the credential details pane, directly under the
password row:

```xml
<TextBlock x:Name="CredentialPasswordMetrics" FontSize="12" Margin="0,4,0,0"
           Foreground="{StaticResource TextSecondaryBrush}"/>
```

Extract the formatting so both call sites share it, rather than duplicating the
`string.Format` pair:

```csharp
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
```

Use it from `UpdateStrengthIndicator` for `PasswordMetrics`, and from
`ShowCredentialDetails` for `CredentialPasswordMetrics` with
`credential.Password`. In `ShowCredentialDetails` the password is already read to
build the masking dots, so this adds no new exposure.

- [ ] **Step 5: Build and run the suite**

```bash
dotnet build CipherVault.sln --no-incremental
dotnet test CipherVault.Tests/CipherVault.Tests.csproj
```

Expected: `Ошибок: 0`; all PASS.

- [ ] **Step 6: Verify by hand**

Launch, unlock a vault, open the generator. Confirm: a 16-character password with all classes shows roughly `103 bits · cracked in 3M+ years`; typing a short weak password drops both figures; clearing the field empties the line; switching to Russian shows `бит · взлом за`.

Then select a saved credential and confirm the same line appears under its
password, and that selecting a credential with a weak password shows a
correspondingly small figure.

- [ ] **Step 7: Commit**

```bash
git add MainWindow.xaml MainWindow.xaml.cs Services/LocalizationService.cs
git commit -m "Show entropy and crack time for generated and saved passwords

Both figures were computed and thrown away - only Score was ever read."
```

---

### Task 8: Move the design tokens onto the WPF UI theme

**Files:**
- Modify: `App.xaml` (colours, brushes and the control styles)

**Interfaces:**
- Consumes: the merged dictionaries from Task 2.
- Produces: the same `StaticResource` keys as today, now derived from the library theme. Tasks 9-13 rely on the keys keeping their names.

- [ ] **Step 1: Keep the key names, change what they point at**

Every existing key stays — `PrimaryDarkBrush`, `SecondaryDarkBrush`, `CardBackgroundBrush`, `BorderBrush`, `TextPrimaryBrush`, `TextSecondaryBrush`, `TextMutedBrush`, the five accent brushes and `AccentGradient`. Markup all over `MainWindow.xaml` references them; renaming any of them breaks a screen silently.

Repoint the surface and text keys at the library theme so our panels and the library controls cannot drift apart:

```xml
<SolidColorBrush x:Key="PrimaryDarkBrush" Color="{DynamicResource ApplicationBackgroundColor}"/>
<SolidColorBrush x:Key="SecondaryDarkBrush" Color="{DynamicResource ControlFillColorDefault}"/>
<SolidColorBrush x:Key="CardBackgroundBrush" Color="{DynamicResource CardBackgroundFillColorDefault}"/>
<SolidColorBrush x:Key="BorderBrush" Color="{DynamicResource ControlStrokeColorDefault}"/>
<SolidColorBrush x:Key="TextPrimaryBrush" Color="{DynamicResource TextFillColorPrimary}"/>
<SolidColorBrush x:Key="TextSecondaryBrush" Color="{DynamicResource TextFillColorSecondary}"/>
<SolidColorBrush x:Key="TextMutedBrush" Color="{DynamicResource TextFillColorTertiary}"/>
```

Keep the five accent colours as literal hex — the library has no equivalent for a five-colour category palette, and the credential avatar gradient depends on them.

If a `DynamicResource` key above does not resolve at runtime (the control renders transparent or black), find the actual key by opening `Wpf.Ui`'s theme dictionary in the NuGet package and use the real name; do not fall back to hardcoding a colour.

**Confirmed during Task 2 by probing the merged dictionaries directly:**
`ControlsDictionary` carries implicit styles for `Button`, `TextBox`, `PasswordBox`,
`CheckBox`, `ComboBox`, `Slider`, `ListBox` and `ProgressBar`. Deleting our styles
therefore leaves those controls styled, not bare. It also means the **native**
`PasswordBox` gets the Fluent look without being swapped for `ui:PasswordBox`, so
the security carve-out costs nothing visually.

- [ ] **Step 2: Delete the control styles the library now provides**

Remove these styles and let the library's implicit styles apply: `ModernTextBox`, `ModernComboBox`, `ModernComboBoxItem`, `ModernCheckBox`, `ModernSlider`, `PrimaryButton`, `SecondaryButton`, `DangerButton`, `IconButton`.

For each deleted key, remove the matching `Style="{StaticResource ...}"` attribute in `MainWindow.xaml`. For buttons, set the intent instead: `<ui:Button Appearance="Primary">` for what was `PrimaryButton`, `Appearance="Secondary"` for `SecondaryButton`, `Appearance="Danger"` for `DangerButton`.

Keep and adapt: `ModernPasswordBox` (the native `PasswordBox` has no library style — this is the one that keeps the master-password fields looking like everything else), `StrengthProgressBar`, `CredentialListBox`, `CredentialListBoxItem`, `VaultListBox`, `VaultListBoxItem`, `LogoButton`.

- [ ] **Step 3: Build**

```bash
dotnet build CipherVault.sln --no-incremental
```

Expected: `Ошибок: 0`. A `Cannot find resource named 'X'` at runtime rather than build time is the usual failure here — go to Step 4 before assuming success.

- [ ] **Step 4: Walk every screen**

Launch and visit, in order: vault list, create-vault form, unlock form, the locked-out state (five wrong passwords), the main list, a credential's details, add/edit, the generator, settings, and a confirmation dialog. Any control that renders transparent, black-on-black or unstyled is an unresolved resource key — fix it before committing.

- [ ] **Step 5: Run the suite**

Run: `dotnet test CipherVault.Tests/CipherVault.Tests.csproj`
Expected: PASS. The Task 1 guard must still be green — Step 2 touched `PasswordBox` styling.

- [ ] **Step 6: Commit**

```bash
git add App.xaml MainWindow.xaml
git commit -m "Derive the palette from the WPF UI theme

Key names are unchanged because the markup references them everywhere.
Hand-rolled control styles the library supplies are gone; ModernPasswordBox
stays, because the native PasswordBox has no library style and has to keep
matching the rest by hand."
```

---

### Task 9: Replace the emoji with Fluent icons

**Files:**
- Modify: `MainWindow.xaml` (16 places across 9 emoji, plus the search field)
- Modify: `Services/LocalizationService.cs` (tooltip keys, both languages)

**Interfaces:**
- Consumes: the `ui` namespace from Task 2.
- Produces: nothing.

- [ ] **Step 1: Replace each emoji**

Emoji render from the OS emoji font, differ between Windows builds, and cannot inherit `Foreground`, so they do not follow the theme or hover state. Replace each with `ui:SymbolIcon`. Exact `SymbolRegular` member names are resolved against the enum — a wrong name is a compile error, so guessing is safe here.

| Emoji | Where | Replace with | Size |
|---|---|---|---|
| 📋 clipboard (4 places) | copy username / email / website / password | `Copy24` | 20 |
| ✕ (3 places) | close dialog, close panel | `Dismiss24` | 20 |
| ⚙ (2 places) | title bar, main screen | `Settings24` | 24 |
| 👁️ (2 places) | reveal password, reveal generated | `Eye24`, swapped to `EyeOff24` while revealed | 20 |
| 🔐 | logo | `ShieldKeyhole24` | 24 |
| ✏️ | edit credential | `Edit24` | 20 |
| 🗑️ | delete credential | `Delete24` | 20 |
| 🎲 | generate | `Key24` | 20 |
| 🔄 | regenerate | `ArrowSync24` | 20 |

`ShieldKeyhole24`, `EyeOff24` and `ArrowSync24` were confirmed present in `Wpf.Ui.dll`. The rest are the conventional Fluent System Icons names; if any does not exist the build fails with `CS0117` on `SymbolRegular`, so substitute the nearest real member and move on — a wrong name cannot reach runtime.

Pattern for an icon-only button:

```xml
<ui:Button Icon="{ui:SymbolIcon Copy24}" Appearance="Transparent"
           ToolTip="{Binding Source={StaticResource Loc}, Path=[CopyPassword]}"
           Click="CopyPassword_Click"/>
```

If the codebase has no binding source for localization, keep assigning tooltips from code-behind where the other localized strings are assigned, and use a plain `ToolTip="Copy password"` placeholder in markup that code-behind overwrites at load.

- [ ] **Step 2: Give the search field its icon**

There is no magnifier in the markup today — the search field simply has none. Replace the search `TextBox` with:

```xml
<ui:TextBox x:Name="SearchBox" Icon="{ui:SymbolIcon Search24}"
            PlaceholderText="Search"
            Text="{Binding SearchQuery, UpdateSourceTrigger=PropertyChanged}"/>
```

Keep the existing `x:Name` and binding exactly as they are in the current markup.

- [ ] **Step 3: Add tooltips**

Every icon-only button needs one — an emoji button with no label and no tooltip is unusable for anyone who does not already know the app. Add keys for copy username, copy email, copy website, copy password, reveal password, edit, delete, generate, regenerate, settings and close, in both languages.

- [ ] **Step 4: Build and walk the screens**

```bash
dotnet build CipherVault.sln --no-incremental
```

Expected: `Ошибок: 0`. A `CS0117` on `SymbolRegular` means that icon name does not exist — pick the nearest real one.

Launch and confirm every former emoji is now a crisp monochrome icon that changes colour on hover, and that every icon button shows a tooltip.

- [ ] **Step 5: Run the suite and commit**

```bash
dotnet test CipherVault.Tests/CipherVault.Tests.csproj
git add MainWindow.xaml Services/LocalizationService.cs
git commit -m "Replace emoji with Fluent icons and add tooltips

Emoji come from the OS emoji font, so they differ between Windows builds
and cannot inherit the foreground colour - they never followed the theme or
the hover state. Icon-only buttons also had no tooltips at all."
```

---

### Task 10: Restyle the login screen

**Files:**
- Modify: `MainWindow.xaml` (`LoginScreen`, `VaultSelectionPanel`, `CreateVaultForm`, `UnlockForm`)

**Interfaces:**
- Consumes: tokens from Task 8, icons from Task 9.
- Produces: nothing.

- [ ] **Step 1: Vault list as cards**

Wrap each vault list item's content in `<ui:Card>`; drop the hand-rolled `Border` with `CornerRadius` where the card replaces it. Keep `VaultListBox`, `VaultListBoxItem` and every `x:Name` untouched.

- [ ] **Step 2: Forms**

Convert plain `TextBox` to `ui:TextBox` with `PlaceholderText`, replacing separate label `TextBlock`s where the placeholder now carries the label. **Leave `CreateMasterPassword`, `ConfirmMasterPassword` and `UnlockPassword` as native `PasswordBox`** with `Style="{StaticResource ModernPasswordBox}"` — this is the constraint from the spec and Task 1 enforces it.

- [ ] **Step 3: The lockout state**

Give the countdown its own visual treatment: an `ui:InfoBar` with `Severity="Caution"` holding `LoginStatusMessage`, rather than a bare red line. Keep the element name.

- [ ] **Step 4: Build, walk, test, commit**

```bash
dotnet build CipherVault.sln --no-incremental
dotnet test CipherVault.Tests/CipherVault.Tests.csproj
```

Walk: vault list, create form (including the mismatch and too-short errors), unlock form, five wrong passwords to reach the lockout, then wait it out.

```bash
git add MainWindow.xaml
git commit -m "Restyle the login screen on the Fluent design system"
```

---

### Task 11: Restyle the main screen

**Files:**
- Modify: `MainWindow.xaml` (`MainApp`, `AddEditPanel`, `GeneratorPanel`, `NoSelectionPanel`)

**Interfaces:**
- Consumes: tokens from Task 8, icons from Task 9, the metrics line from Task 7.
- Produces: nothing.

- [ ] **Step 1: List and detail**

Credential rows become `ui:Card` content; the detail pane's field rows become `ui:CardControl` where a row is a label plus a value plus an action. Keep the avatar `Border` with its `AccentGradient` — that is the app's own identity, not something the library supplies.

- [ ] **Step 2: Empty state**

`NoSelectionPanel` gets an icon, a one-line heading and a muted explanatory line, instead of bare text.

- [ ] **Step 3: Generator panel**

Slider to `ui:Slider`; the four character-class checkboxes to `ui:ToggleSwitch`; keep the strength meter markup and `PasswordMetrics` from Task 7 exactly where they are.

- [ ] **Step 4: Build, walk, test, commit**

```bash
dotnet build CipherVault.sln --no-incremental
dotnet test CipherVault.Tests/CipherVault.Tests.csproj
```

Walk: empty vault, a vault with several credentials, selecting one, add, edit, delete, all four copy buttons, reveal, and the generator with every toggle combination including all four off.

```bash
git add MainWindow.xaml
git commit -m "Restyle the main screen on the Fluent design system"
```

---

### Task 12: Restyle settings and the dialog overlay

**Files:**
- Modify: `MainWindow.xaml` (`SettingsPanel`, `DialogOverlay`)

**Interfaces:**
- Consumes: tokens from Task 8, icons from Task 9, the toggle from Task 5.
- Produces: nothing.

- [ ] **Step 1: Settings as grouped cards**

Group the settings into `ui:CardExpander` sections: vault location; appearance and security (language, logging, screenshot protection); destructive actions. Each section follows this shape, keeping every existing `x:Name` and handler on the controls inside:

```xml
<ui:CardExpander Margin="0,0,0,12" IsExpanded="True">
    <ui:CardExpander.Header>
        <StackPanel Orientation="Horizontal">
            <ui:SymbolIcon Symbol="ShieldKeyhole24" FontSize="20" Margin="0,0,10,0"/>
            <TextBlock x:Name="SecuritySectionLabel" Text="Security"
                       VerticalAlignment="Center" FontWeight="SemiBold"/>
        </StackPanel>
    </ui:CardExpander.Header>

    <StackPanel Margin="0,4,0,0">
        <!-- the existing language, logging and screenshot-protection rows move here
             unchanged, names and handlers intact -->
    </StackPanel>
</ui:CardExpander>
```

"Delete Current Vault" goes in its own section, and its button becomes:

```xml
<ui:Button x:Name="DeleteCurrentVaultBtn" Appearance="Danger"
           Icon="{ui:SymbolIcon Delete24}" Content="Delete Current Vault"
           Click="DeleteCurrentVaultBtn_Click"/>
```

Add localization keys for the three new section headings in both languages and assign them where the other settings labels are assigned in code-behind.

- [ ] **Step 2: Dialog overlay**

Keep `DialogOverlay` and every `x:Name` inside it. Put the dialog body in a card and give the confirm button of destructive dialogs the danger appearance:

```xml
<Grid x:Name="DialogOverlay" Grid.Row="1" Visibility="Collapsed" Background="#99000000">
    <ui:Card MaxWidth="420" VerticalAlignment="Center" HorizontalAlignment="Center" Padding="24">
        <StackPanel>
            <TextBlock x:Name="DialogTitle" FontSize="18" FontWeight="SemiBold"
                       TextWrapping="Wrap"/>
            <TextBlock x:Name="DialogMessage" Margin="0,10,0,0" TextWrapping="Wrap"
                       Foreground="{StaticResource TextSecondaryBrush}"/>
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,20,0,0">
                <ui:Button x:Name="DialogCancelBtn" Content="Cancel" Appearance="Secondary"
                           Margin="0,0,8,0" Click="DialogCancelBtn_Click"/>
                <ui:Button x:Name="DialogConfirmBtn" Content="OK" Appearance="Primary"
                           Click="DialogConfirmBtn_Click"/>
            </StackPanel>
        </StackPanel>
    </ui:Card>
</Grid>
```

Check the real element names and handler names in the current `DialogOverlay` markup first and keep whatever is there — the names above are the expected ones, not a licence to rename.

- [ ] **Step 3: Build, walk, test, commit**

```bash
dotnet build CipherVault.sln --no-incremental
dotnet test CipherVault.Tests/CipherVault.Tests.csproj
```

Walk: every settings row, the screenshot-protection confirmation from Task 5, vault deletion confirmation, an info dialog, and the cancel path of each.

```bash
git add MainWindow.xaml
git commit -m "Restyle settings and dialogs on the Fluent design system"
```

---

### Task 13: Animations, and honouring reduced motion

**Files:**
- Create: `Services/MotionSettings.cs`
- Modify: `App.xaml` (shared storyboards and durations)
- Modify: `MainWindow.xaml` (triggers)
- Modify: `MainWindow.xaml.cs` (screen transitions)
- Test: `CipherVault.Tests/MotionSettingsTests.cs` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `MotionSettings.AnimationsEnabled -> bool` and `MotionSettings.Scale(TimeSpan duration) -> TimeSpan`.

- [ ] **Step 1: Write the failing test**

Create `CipherVault.Tests/MotionSettingsTests.cs`:

```csharp
using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class MotionSettingsTests
{
    [Fact]
    public void DurationsPassThroughWhenAnimationIsAllowed()
    {
        Assert.Equal(TimeSpan.FromMilliseconds(180),
            MotionSettings.Scale(TimeSpan.FromMilliseconds(180), animationsEnabled: true));
    }

    [Fact]
    public void DurationsCollapseToZeroWhenMotionIsReduced()
    {
        Assert.Equal(TimeSpan.Zero,
            MotionSettings.Scale(TimeSpan.FromMilliseconds(180), animationsEnabled: false));
    }

    [Fact]
    public void ZeroStaysZeroEitherWay()
    {
        Assert.Equal(TimeSpan.Zero, MotionSettings.Scale(TimeSpan.Zero, animationsEnabled: true));
        Assert.Equal(TimeSpan.Zero, MotionSettings.Scale(TimeSpan.Zero, animationsEnabled: false));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `dotnet test CipherVault.Tests/CipherVault.Tests.csproj --filter "FullyQualifiedName~MotionSettingsTests"`
Expected: FAIL to compile — `MotionSettings` does not exist.

- [ ] **Step 3: Implement**

Create `Services/MotionSettings.cs`:

```csharp
using System.Windows;

namespace CipherVault.Services;

/// <summary>
/// Whether transitions should play. Users who turn animation off in Windows are
/// often doing it for motion sensitivity or on a remote session where animation
/// is painful - an app that ignores that setting is not merely unfashionable.
/// </summary>
public static class MotionSettings
{
    public static bool AnimationsEnabled => SystemParameters.ClientAreaAnimation;

    public static TimeSpan Scale(TimeSpan duration) => Scale(duration, AnimationsEnabled);

    public static TimeSpan Scale(TimeSpan duration, bool animationsEnabled)
        => animationsEnabled ? duration : TimeSpan.Zero;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `dotnet test CipherVault.Tests/CipherVault.Tests.csproj --filter "FullyQualifiedName~MotionSettingsTests"`
Expected: PASS, 3 tests.

- [ ] **Step 5: Add the screen transition**

In `MainWindow.xaml.cs`, add one helper and route the existing show/hide code through it. Screens are switched by `Visibility` in several places (`ShowMainApp`, `ShowVaultSelection`, `LockVault`, the settings handlers) — replace the direct `Visibility = Visibility.Visible` assignments on `LoginScreen`, `MainApp` and `SettingsPanel` with this:

```csharp
    private static readonly TimeSpan ScreenTransition = TimeSpan.FromMilliseconds(180);

    private static void ShowScreen(UIElement screen)
    {
        screen.Visibility = Visibility.Visible;

        var duration = MotionSettings.Scale(ScreenTransition);
        if (duration == TimeSpan.Zero)
        {
            screen.Opacity = 1;
            return;
        }

        var transform = new TranslateTransform(0, 8);
        screen.RenderTransform = transform;
        screen.Opacity = 0;

        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
        screen.BeginAnimation(UIElement.OpacityProperty,
            new DoubleAnimation(0, 1, duration) { EasingFunction = ease });
        transform.BeginAnimation(TranslateTransform.YProperty,
            new DoubleAnimation(8, 0, duration) { EasingFunction = ease });
    }
```

Add `using System.Windows.Media.Animation;` and `using System.Windows.Media;` to the file.

- [ ] **Step 6: Animate the strength bar instead of jumping**

In `UpdateStrengthIndicator`, replace the direct `StrengthFill.Width = ...` assignment with an animation:

```csharp
        var targetWidth = availableWidth * fillPercent / 100.0;
        var barDuration = MotionSettings.Scale(TimeSpan.FromMilliseconds(250));

        if (barDuration == TimeSpan.Zero)
        {
            StrengthFill.BeginAnimation(FrameworkElement.WidthProperty, null);
            StrengthFill.Width = targetWidth;
        }
        else
        {
            StrengthFill.BeginAnimation(FrameworkElement.WidthProperty,
                new DoubleAnimation(targetWidth, barDuration)
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                });
        }
```

Apply the same treatment to the `StrengthFill.Width` assignment in `StrengthGrid_SizeChanged`.

- [ ] **Step 7: Dialog overlay**

The dialog is shown from code, so animate it the same way as a screen. In `MainWindow.xaml.cs`, wherever `DialogOverlay.Visibility = Visibility.Visible` is set, call:

```csharp
    private void ShowDialogOverlay()
    {
        DialogOverlay.Visibility = Visibility.Visible;

        var duration = MotionSettings.Scale(TimeSpan.FromMilliseconds(120));
        var card = (FrameworkElement)((Grid)DialogOverlay).Children[0];

        if (duration == TimeSpan.Zero)
        {
            DialogOverlay.Opacity = 1;
            card.RenderTransform = null;
            return;
        }

        var scale = new ScaleTransform(0.96, 0.96);
        card.RenderTransformOrigin = new Point(0.5, 0.5);
        card.RenderTransform = scale;
        DialogOverlay.Opacity = 0;

        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
        DialogOverlay.BeginAnimation(UIElement.OpacityProperty,
            new DoubleAnimation(0, 1, duration) { EasingFunction = ease });
        scale.BeginAnimation(ScaleTransform.ScaleXProperty,
            new DoubleAnimation(0.96, 1, duration) { EasingFunction = ease });
        scale.BeginAnimation(ScaleTransform.ScaleYProperty,
            new DoubleAnimation(0.96, 1, duration) { EasingFunction = ease });
    }
```

- [ ] **Step 8: Detail pane cross-fade**

Where `SelectedCredential` changes and the detail pane is refreshed, fade the pane rather than swapping instantly:

```csharp
    private void CrossFadeDetails()
    {
        var duration = MotionSettings.Scale(TimeSpan.FromMilliseconds(120));
        if (duration == TimeSpan.Zero)
        {
            return;
        }

        CredentialDetailsPanel.BeginAnimation(UIElement.OpacityProperty,
            new DoubleAnimation(0, 1, duration)
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            });
    }
```

Use the actual name of the details container from the markup instead of `CredentialDetailsPanel` if it differs.

- [ ] **Step 9: Credential list entrance stagger**

Add to `App.xaml`, inside `Application.Resources`, an item entrance the list template can trigger. The cap matters: past ten items a stagger makes opening a large vault feel slow rather than lively, so items beyond the tenth all start together.

```xml
<Storyboard x:Key="ListItemEntrance">
    <DoubleAnimation Storyboard.TargetProperty="Opacity"
                     From="0" To="1" Duration="0:0:0.18">
        <DoubleAnimation.EasingFunction>
            <CubicEase EasingMode="EaseOut"/>
        </DoubleAnimation.EasingFunction>
    </DoubleAnimation>
</Storyboard>
```

Apply it from `CredentialListBoxItem`'s `Loaded` trigger with `BeginTime` set from the item index: `TimeSpan.FromMilliseconds(25 * Math.Min(index, 10))`. If wiring the index through the template proves awkward, drop the stagger and keep a plain fade — it is the least valuable animation here and is not worth contorting the list template for.

- [ ] **Step 10: Build, test, and verify both motion modes**

```bash
dotnet build CipherVault.sln --no-incremental
dotnet test CipherVault.Tests/CipherVault.Tests.csproj
```

Expected: `Ошибок: 0`; all PASS.

Launch and confirm transitions are smooth and short. Then turn animation off in Windows (Settings → Accessibility → Visual effects → Animation effects) and relaunch: every transition must be instant, with nothing half-faded or stuck at opacity 0. Turn it back on.

- [ ] **Step 11: Commit**

```bash
git add Services/MotionSettings.cs App.xaml MainWindow.xaml MainWindow.xaml.cs
git commit -m "Animate screen, dialog and strength-meter transitions

Durations are short on purpose: a password manager is opened to retrieve a
password quickly. Every duration passes through MotionSettings, so turning
animation off in Windows makes transitions instant rather than merely
faster."
```

---

### Task 14: Final pass

**Files:** none created; fixes only.

- [ ] **Step 1: Clean rebuild with no warnings**

```bash
dotnet build CipherVault.sln --no-incremental
```

Expected: `Предупреждений: 0`, `Ошибок: 0`.

- [ ] **Step 2: Whole suite**

```bash
dotnet test CipherVault.Tests/CipherVault.Tests.csproj
```

Expected: every test PASS, including the Task 1 master-password guard.

- [ ] **Step 3: Confirm nothing from the test project is staged**

```bash
git status --short
```

Expected: nothing under `CipherVault.Tests/`.

- [ ] **Step 4: Full manual pass**

In both languages, at the default window size, at the minimum size, maximised, and at 150% display scaling: vault list, create vault, unlock, lockout, main list, credential details, add, edit, delete, all copy buttons, reveal, generator, settings including the screenshot toggle, and both a confirmation and an info dialog.

Then the two security checks that no test covers: `Win+Shift+S` shows black with protection on and shows the window with it off; and after locking the vault, the credential list is empty and the details pane is cleared.

- [ ] **Step 5: Push**

```bash
git push
```

---

## Notes for whoever executes this

**The riskiest thing in this plan is not the code, it is the markup.** `MainWindow.xaml.cs` is 1726 lines and reaches about a hundred elements by name. Deleting or renaming an `x:Name` compiles fine and fails at runtime, often only on a screen you did not open. That is why every markup task ends with walking the screens rather than trusting a green build.

**If a task's verification fails, stop rather than continue.** These tasks build on each other: restyling screens on top of a broken token layer produces a mess that is hard to unpick.

**Things deliberately left out**, recorded so nobody adds them by accident: a light theme and its switcher; removing the remaining dead code (`SecureInputBox`, `SecureSession`, `MigrateVault`); authenticating `config.json`. All three are follow-ups in the spec.
