using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Web.WebView2.Core;
using Microsoft.Win32;
using OTSSystemSanitizer.Core;

namespace OTSSecuritySuite.Desktop;

public partial class MainWindow : Window
{
    private Process? _engine;
    private CancellationTokenSource? _scanCancellation;
    private CancellationTokenSource? _whiteAuditCancellation;
    private Process? _whiteAuditProcess;
    private readonly QuarantineService _quarantine = new();
    private readonly HashSet<string> _reviewed = new(StringComparer.Ordinal);
    private readonly string _engineDirectory = Path.Combine(AppContext.BaseDirectory, "engines");
    private string? _lastWhiteOutput;
    private string? _launchRepository;
    private bool _isClosing;

    public MainWindow()
    {
        InitializeComponent();
        // Custom protocol launches from the browser extension only provide a public URL.
        // Never run arbitrary command-line arguments from a protocol handler.
        foreach (var arg in Environment.GetCommandLineArgs().Skip(1))
        {
            if (!arg.StartsWith("ots-security://scan?", StringComparison.OrdinalIgnoreCase)) continue;
            if (!Uri.TryCreate(arg, UriKind.Absolute, out var parsed)) continue;
            foreach (var part in parsed.Query.TrimStart('?').Split('&'))
            {
                var kv = part.Split('=', 2);
                if (kv.Length != 2 || kv[0] != "url") continue;
                var candidate = Uri.UnescapeDataString(kv[1]);
                if (Uri.TryCreate(candidate, UriKind.Absolute, out var repo) &&
                    repo.Scheme == "https" && (repo.Host == "github.com" || repo.Host == "bitbucket.org"))
                    _launchRepository = candidate;
            }
        }
        RefreshVault();
    }

    private async void OnWindowLoaded(object sender, RoutedEventArgs e)
    {
        await StartRepositoryEngineAsync();
    }

    private async Task StartRepositoryEngineAsync()
    {
        string exe = Path.Combine(_engineDirectory, "OTSScannerEngine.exe");
        if (!File.Exists(exe))
        {
            RepositoryLoading.Text = "Repository engine is missing from this installation. Run the full suite installer.";
            return;
        }
        try
        {
            var psi = new ProcessStartInfo(exe) {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
                CreateNoWindow = true, WorkingDirectory = _engineDirectory
            };
            psi.ArgumentList.Add("--no-browser");
            psi.ArgumentList.Add("--ephemeral");
            psi.ArgumentList.Add("--print-url");
            _engine = Process.Start(psi) ?? throw new InvalidOperationException("Engine did not start.");
            // The first line contains the one-time local session URL; never print it in diagnostics.
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
            var line = await _engine.StandardOutput.ReadLineAsync(timeout.Token);
            if (line is null || !line.StartsWith("OTS_SCAN_URL=", StringComparison.Ordinal))
                throw new InvalidOperationException("Engine did not provide a local session URL.");
            var target = line["OTS_SCAN_URL=".Length..];
            if (!Uri.TryCreate(target, UriKind.Absolute, out var address) || !address.IsLoopback || address.Scheme != "http")
                throw new InvalidOperationException("Engine returned an invalid local address.");
            string profile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Ohana Tech Solutions", "Security Suite", "WebView2");
            Directory.CreateDirectory(profile);
            var env = await CoreWebView2Environment.CreateAsync(null, profile);
            await RepositoryBrowser.EnsureCoreWebView2Async(env);
            RepositoryBrowser.CoreWebView2.Settings.AreDevToolsEnabled = false;
            RepositoryBrowser.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
            RepositoryBrowser.CoreWebView2.Settings.IsWebMessageEnabled = false;
            // Only the embedded local scanner is permitted to interact with the suite.
            // Block new browser windows, external pop-ups, and web permission prompts.
            RepositoryBrowser.CoreWebView2.NewWindowRequested += (_, popup) => {
                popup.Handled = true;
            };
            RepositoryBrowser.CoreWebView2.PermissionRequested += (_, permission) => {
                permission.State = CoreWebView2PermissionState.Deny;
            };
            RepositoryBrowser.CoreWebView2.NavigationStarting += (_, nav) => {
                if (!Uri.TryCreate(nav.Uri, UriKind.Absolute, out var dest) ||
                    dest.Scheme != "http" || dest.Host != "127.0.0.1" || dest.Port != address.Port)
                    nav.Cancel = true;
            };
            RepositoryBrowser.Visibility = Visibility.Visible;
            RepositoryLoading.Visibility = Visibility.Collapsed;
            RepositoryBrowser.CoreWebView2.Navigate(target);
            if (_launchRepository is { Length: > 0 })
            {
                // The scanner's own query handling is used; the external repo is never executed.
                RepositoryBrowser.NavigationCompleted += (_, _) => {
                    if (_launchRepository is null) return;
                    var repo = _launchRepository;
                    _launchRepository = null;
                    _ = RepositoryBrowser.ExecuteScriptAsync("document.getElementById('repoUrl').value = " +
                        System.Text.Json.JsonSerializer.Serialize(repo) + ";");
                };
            }
        }
        catch (Exception ex)
        {
            RepositoryLoading.Text = "Could not launch repository scanner: " + ex.Message;
            StopEngine();
        }
    }
    private void StopEngine()
    {
        try { if (_engine is { HasExited: false }) _engine.Kill(entireProcessTree: true); }
        catch (InvalidOperationException) { }
        catch (System.ComponentModel.Win32Exception) { }
        try { _engine?.Dispose(); } catch { }
        _engine = null;
    }
    private void OnWindowClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        _isClosing = true;
        _scanCancellation?.Cancel();
        _whiteAuditCancellation?.Cancel();
        StopWhiteAuditProcess();
        StopEngine();
    }
    private void SetPanel(Grid selected)
    {
        foreach (var p in new[] { RepositoryPanel, WhitePanel, SystemPanel, CleanupPanel })
            p.Visibility = p == selected ? Visibility.Visible : Visibility.Collapsed;
    }
    private void ShowRepository(object sender, RoutedEventArgs e) => SetPanel(RepositoryPanel);
    private void ShowWhite(object sender, RoutedEventArgs e) => SetPanel(WhitePanel);
    private void ShowSystem(object sender, RoutedEventArgs e) => SetPanel(SystemPanel);
    private void ShowCleanup(object sender, RoutedEventArgs e) { RefreshVault(); SetPanel(CleanupPanel); }

    private void BrowseWhiteFolder(object sender, RoutedEventArgs e)
    {
        var d = new OpenFolderDialog { Title = "Choose a local repository for W.H.I.T.E." };
        if (d.ShowDialog(this) == true) WhiteFolder.Text = d.FolderName;
    }
    private void StopWhiteAuditProcess()
    {
        try
        {
            if (_whiteAuditProcess is { HasExited: false })
                _whiteAuditProcess.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException) { } // Already exited.
        catch (System.ComponentModel.Win32Exception) { } // OS denied termination.
    }

    private async Task<string> ReadBoundedAuditOutputAsync(StreamReader reader, int maxCharacters, CancellationToken cancellation)
    {
        var builder = new StringBuilder();
        var buffer = new char[8192];
        while (true)
        {
            int count = await reader.ReadAsync(buffer.AsMemory(), cancellation).ConfigureAwait(false);
            if (count == 0) return builder.ToString();
            if (count > maxCharacters - builder.Length)
            {
                // Do not let untrusted repository findings or broken CLI diagnostics grow without bound.
                StopWhiteAuditProcess();
                throw new InvalidDataException("Audit engine output exceeded its safe size limit.");
            }
            builder.Append(buffer, 0, count);
        }
    }

    private void CancelWhiteAudit(object sender, RoutedEventArgs e)
    {
        if (_whiteAuditCancellation is null) return;
        WhiteStatus.Text = "Cancelling audit...";
        _whiteAuditCancellation.Cancel();
        StopWhiteAuditProcess();
    }

    private async void RunWhiteAudit(object sender, RoutedEventArgs e)
    {
        // Only one child audit may own this window at any time.
        if (_whiteAuditCancellation is not null) return;
        var target = WhiteFolder.Text.Trim();
        if (!Directory.Exists(target)) { WhiteStatus.Text = "Choose an existing local repository folder."; return; }
        string binary = Path.Combine(_engineDirectory, "OTSWhiteAudit.exe");
        if (!File.Exists(binary)) { WhiteStatus.Text = "W.H.I.T.E. audit engine missing from installation."; return; }

        _lastWhiteOutput = null; // Never export a stale report after a failed/cancelled run.
        WhiteOutput.Clear();
        using var cancellation = new CancellationTokenSource();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(12));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token, timeout.Token);
        _whiteAuditCancellation = cancellation;
        WhiteRun.IsEnabled = false;
        WhiteCancel.IsEnabled = true;
        WhiteStatus.Text = "Auditing source and configuration...";
        try
        {
            var psi = new ProcessStartInfo(binary) {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true,
                RedirectStandardError = true, WorkingDirectory = AppContext.BaseDirectory
            };
            psi.Environment["GIT_TERMINAL_PROMPT"] = "0";
            psi.ArgumentList.Add(target);
            psi.ArgumentList.Add("--format"); psi.ArgumentList.Add("json");
            if (HistoryScan.IsChecked == true) psi.ArgumentList.Add("--history");
            if (DependencyScan.IsChecked != true) psi.ArgumentList.Add("--no-sca");
            using var process = Process.Start(psi) ?? throw new InvalidOperationException("Audit engine could not start.");
            _whiteAuditProcess = process;
            try
            {
                // Drain both pipes simultaneously to avoid child-process output deadlocks.
                var stdout = ReadBoundedAuditOutputAsync(process.StandardOutput, 16 * 1024 * 1024, linked.Token);
                var stderr = ReadBoundedAuditOutputAsync(process.StandardError, 128 * 1024, linked.Token);
                await process.WaitForExitAsync(linked.Token);
                string output = await stdout;
                await stderr; // Drain for child liveness; do not display potentially sensitive raw stderr.
                linked.Token.ThrowIfCancellationRequested();
                if (_isClosing) return;
                if (string.IsNullOrWhiteSpace(output))
                {
                    WhiteStatus.Text = "Audit returned no JSON report. Check the audit configuration and retry.";
                    return;
                }
                using (var report = System.Text.Json.JsonDocument.Parse(output))
                {
                    if (report.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object)
                        throw new InvalidDataException("Audit output did not contain a JSON report object.");
                }
                if (process.ExitCode is not (0 or 1 or 2))
                {
                    WhiteStatus.Text = "Audit engine failed (exit " + process.ExitCode + "); no report is exportable.";
                    return;
                }
                _lastWhiteOutput = output;
                WhiteOutput.Text = output;
                WhiteStatus.Text = process.ExitCode switch {
                    0 => "Audit completed · no findings at the configured failure threshold",
                    1 => "Audit completed · findings require review",
                    2 => "Audit incomplete · review the report and configuration",
                    _ => "Audit exited with status " + process.ExitCode
                };
            }
            finally
            {
                // Timeout, user cancellation, window close and abnormal exit all reap the child.
                StopWhiteAuditProcess();
                _whiteAuditProcess = null;
            }
        }
        catch (OperationCanceledException)
        {
            if (!_isClosing)
                WhiteStatus.Text = timeout.IsCancellationRequested
                    ? "Audit timed out after 12 minutes; termination requested."
                    : "Audit cancelled; termination requested.";
        }
        catch (Exception ex)
        {
            if (!_isClosing) WhiteStatus.Text = "Audit could not finish: " + ex.Message;
        }
        finally
        {
            _whiteAuditCancellation = null;
            if (!_isClosing)
            {
                WhiteRun.IsEnabled = true;
                WhiteCancel.IsEnabled = false;
            }
        }
    }
    private void ExportWhiteReport(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_lastWhiteOutput)) { WhiteStatus.Text = "Run an audit before exporting."; return; }
        var dialog = new SaveFileDialog { Filter = "JSON report|*.json", FileName = "OTS-White-Audit.json" };
        if (dialog.ShowDialog(this) == true) File.WriteAllText(dialog.FileName, _lastWhiteOutput, Encoding.UTF8);
    }

    private async void RunQuick(object sender, RoutedEventArgs e) => await RunSystemScan(ScanMode.Quick);
    private async void RunDeep(object sender, RoutedEventArgs e) => await RunSystemScan(ScanMode.Deep);
    private async Task RunSystemScan(ScanMode mode)
    {
        _scanCancellation?.Cancel();
        _scanCancellation = new CancellationTokenSource();
        QuickButton.IsEnabled = DeepButton.IsEnabled = false;
        SystemStatus.Text = mode == ScanMode.Quick ? "Quick scan started..." : "Deep scan started...";
        var progress = new Progress<ScanProgress>(p => { if (!_isClosing) SystemStatus.Text =
            $"{p.Phase} · {p.Files:N0} files reviewed · {p.Skipped:N0} inaccessible"; });
        try
        {
            var result = await ThreatScanner.RunAsync(mode, progress, _scanCancellation.Token);
            SystemFindings.ItemsSource = result.Findings;
            SystemStatus.Text = $"Scan finished · {result.Files:N0} files · {result.Findings.Count} findings · " +
                $"{result.Skipped} inaccessible · {result.Elapsed:g}";
        }
        catch (OperationCanceledException) { SystemStatus.Text = "Scan cancelled."; }
        catch (Exception ex) { SystemStatus.Text = "Scan failed: " + ex.Message; }
        finally { QuickButton.IsEnabled = DeepButton.IsEnabled = true; }
    }
    private async void RunDefender(object sender, RoutedEventArgs e)
    {
        SystemStatus.Text = "Requesting Microsoft Defender Quick Scan...";
        try { SystemStatus.Text = await DefenderIntegration.RunScanAsync(ScanMode.Quick, CancellationToken.None); }
        catch (Exception ex) { SystemStatus.Text = "Defender request failed: " + ex.Message; }
    }
    private void OpenSanitizer(object sender, RoutedEventArgs e)
    {
        string binary = Path.Combine(_engineDirectory, "OTSSystemSanitizer.exe");
        if (!File.Exists(binary)) { SystemStatus.Text = "Full Sanitizer module is missing."; return; }
        try { Process.Start(new ProcessStartInfo(binary) { UseShellExecute = true }); }
        catch (Exception ex) { SystemStatus.Text = "Could not open System Sanitizer: " + ex.Message; }
    }
    private void InvestigateFinding(object sender, RoutedEventArgs e)
    {
        if (SystemFindings.SelectedItem is not ThreatFinding finding) return;
        MessageBox.Show(this, ThreatInvestigator.Explain(finding), "Finding investigation", MessageBoxButton.OK, MessageBoxImage.Information);
    }
    private void QuarantineFinding(object sender, RoutedEventArgs e)
    {
        if (SystemFindings.SelectedItem is not ThreatFinding finding) return;
        if (MessageBox.Show(this, "Move the selected user file into encrypted quarantine?\n\n"+finding.Path,
            "Confirm quarantine", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try
        {
            _quarantine.Quarantine(finding.Path, ThreatInvestigator.Explain(finding));
            SystemStatus.Text = "File quarantined. Review it in Quarantine & Cleanup.";
            RefreshVault();
        }
        catch (Exception ex) { SystemStatus.Text = "Quarantine failed: " + ex.Message; }
    }
    private void RefreshQuarantine(object sender, RoutedEventArgs e) => RefreshVault();
    private void RefreshVault() => QuarantineItems.ItemsSource = _quarantine.List();
    private void InvestigateQuarantined(object sender, RoutedEventArgs e)
    {
        if (QuarantineItems.SelectedItem is not QuarantinedFile item) return;
        MessageBox.Show(this, ThreatInvestigator.QuarantineReport(item), "Quarantine review",
            MessageBoxButton.OK, MessageBoxImage.Information);
        _reviewed.Add(item.Id);
    }
    private void RestoreQuarantined(object sender, RoutedEventArgs e)
    {
        if (QuarantineItems.SelectedItem is not QuarantinedFile item) return;
        if (MessageBox.Show(this, "Restore this file to its original location?\n" + item.OriginalPath,
            "Confirm restore", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        try { _quarantine.Restore(item); RefreshVault(); CleanupStatus.Text = "File restored."; }
        catch (Exception ex) { CleanupStatus.Text = "Restore failed: " + ex.Message; }
    }
    private void DestroyQuarantined(object sender, RoutedEventArgs e)
    {
        if (QuarantineItems.SelectedItem is not QuarantinedFile item) return;
        if (!_reviewed.Contains(item.Id)) { CleanupStatus.Text = "Review the selected quarantine item before destroying it."; return; }
        if (MessageBox.Show(this, "PERMANENTLY destroy this reviewed quarantine item? This cannot be undone.\n"+item.OriginalPath,
            "Permanent removal", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try { _quarantine.Destroy(item); _reviewed.Remove(item.Id); RefreshVault(); CleanupStatus.Text = "Reviewed quarantine item removed."; }
        catch (Exception ex) { CleanupStatus.Text = "Removal failed: " + ex.Message; }
    }
    private void DiscoverCleanup(object sender, RoutedEventArgs e)
    {
        var candidates = CleanupService.Discover(BrowserCache.IsChecked == true);
        CleanupItems.ItemsSource = candidates;
        CleanupStatus.Text = $"{candidates.Count:N0} cleanup candidates. Select the specific files you want to remove.";
    }
    private void RemoveCleanup(object sender, RoutedEventArgs e)
    {
        var selected = CleanupItems.SelectedItems.Cast<CleanupCandidate>().ToArray();
        if (selected.Length == 0) { CleanupStatus.Text = "Select one or more cleanup files first."; return; }
        if (MessageBox.Show(this, $"Permanently remove {selected.Length:N0} selected old temporary files?",
            "Confirm space recovery", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        var result = CleanupService.RemoveSelected(selected);
        CleanupStatus.Text = $"Removed {result.Removed} files, {result.BytesRemoved:N0} bytes. Failed: {result.Failures.Count}.";
        DiscoverCleanup(sender,e);
    }
}
