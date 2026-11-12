using System.Runtime.InteropServices;
using System.Windows;

namespace OTSSecuritySuite.Desktop;

public partial class App : Application
{
    internal const string AppUserModelID = "OhanaTechSolutions.OTSSecuritySuite";

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SetCurrentProcessExplicitAppUserModelID(string appID);

    protected override void OnStartup(StartupEventArgs e)
    {
        // Must happen before the first WPF window is created so Windows binds
        // taskbar grouping, pinning and Alt+Tab to this suite, not an old browser app.
        if (OperatingSystem.IsWindows())
            _ = SetCurrentProcessExplicitAppUserModelID(AppUserModelID);
        base.OnStartup(e);
    }
}
