using System.Windows;
using System.Windows.Threading;

namespace CipherVault;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // A password manager that dies silently can lose the vault mid-write, and an
        // unhandled exception on the UI thread otherwise tears the process down with
        // no explanation. Report it and keep running.
        DispatcherUnhandledException += OnDispatcherUnhandledException;
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        e.Handled = true;

        MessageBox.Show(
            e.Exception.Message,
            "CipherVault",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
    }
}
