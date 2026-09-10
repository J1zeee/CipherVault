using System.Windows;

namespace CipherVault;

public static class Program
{
    [STAThread]
    public static void Main()
    {
#if RELEASE
        StartupSecurity.EnsureSingleInstance();

        if (StartupSecurity.DetectDebugger())
        {
            StartupSecurity.ExitWithJitter();
            return;
        }

        StartupSecurity.ApplyMitigationPolicy();
#endif

        var app = new App();
        app.InitializeComponent();
        app.Run();
    }
}