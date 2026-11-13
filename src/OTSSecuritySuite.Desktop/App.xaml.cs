using System.Runtime.InteropServices;
using System.Windows;

namespace OTSSecuritySuite.Desktop;

public partial class App : Application
{
    internal const string AppUserModelID = "OhanaTechSolutions.OTSSecuritySuite";
    private ProtocolActivation? _broker;

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SetCurrentProcessExplicitAppUserModelID(string appID);

    protected override void OnStartup(StartupEventArgs e)
    {
        if (OperatingSystem.IsWindows())
            _ = SetCurrentProcessExplicitAppUserModelID(AppUserModelID);

        _broker = new ProtocolActivation();
        if (!_broker.TryBecomePrimary())
        {
            // The existing process owns all local scanner children. Forward
            // a validated action and exit instead of launching another engine.
            var uri = e.Args.FirstOrDefault() ?? "ots-security://scan";
            bool delivered = false;
            try { delivered = _broker.SendToPrimaryAsync(uri).GetAwaiter().GetResult(); }
            catch (OperationCanceledException) { }
            if (!delivered)
                MessageBox.Show("The running OTS Security Suite could not receive this request. " +
                    "Open its existing window to continue.", "OTS Security Suite",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            Shutdown(delivered ? 0 : 2);
            return;
        }

        base.OnStartup(e);
        var window = new MainWindow();
        MainWindow = window;
        _broker.StartListening(uri => Dispatcher.BeginInvoke(() =>
        {
            if (!window.Dispatcher.HasShutdownStarted)
                window.ReceiveProtocol(uri);
        }));
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _broker?.Dispose();
        base.OnExit(e);
    }
}
