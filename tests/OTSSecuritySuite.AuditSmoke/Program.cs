using System.Diagnostics;
using System.IO;
using OTSSecuritySuite.Desktop;

var cases = new (string Name, Func<Task> Action)[]
{
    ("bounded valid stdout and private stderr", ValidOutput),
    ("nonzero exit code is faithfully returned", NonzeroExit),
    ("user cancellation reaps process", Cancellation),
    ("timeout reaps process", Timeout),
    ("stdout overflow terminates process", StdoutOverflow),
    ("stderr overflow terminates process", StderrOverflow),
    ("only one concurrent audit is allowed", PreventDuplicates),
    ("invalid shell and nonredirected process rejected", RejectUnsafeConfiguration),
    ("report export is atomic and preserves old JSON on invalid input", AtomicJsonExport),
    ("report export rejects absent directory and cleans temp output", ExportFailureCleanly),
    ("quarantine registry preserves current and legacy vaults", BothQuarantineVaults),
    ("quarantine registry does not create a legacy vault", DoesNotCreateLegacyVault),
};
int passed = 0;
foreach (var (name, action) in cases)
{
    try
    {
        await action();
        Console.WriteLine("PASS " + name);
        passed++;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine("FAIL " + name + " : " + ex);
    }
}
Console.WriteLine($"Audit runner tests: {passed}/{cases.Length} PASS");
return passed == cases.Length ? 0 : 1;

static ProcessStartInfo Powershell(string command)
{
    var psi = new ProcessStartInfo("powershell.exe")
    {
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true
    };
    psi.ArgumentList.Add("-NoProfile");
    psi.ArgumentList.Add("-NonInteractive");
    psi.ArgumentList.Add("-Command");
    psi.ArgumentList.Add(command);
    return psi;
}

static async Task ValidOutput()
{
    var runner = new WhiteAuditRunner();
    var report = await runner.RunAsync(
        Powershell("[Console]::Error.WriteLine('SYNTHETIC_PRIVATE_SENTINEL'); [Console]::Out.Write('{}')"),
        TimeSpan.FromSeconds(15));
    Assert(report.ExitCode == 0, "Expected success exit code");
    Assert(report.StandardOutput.Trim() == "{}", "Expected only JSON stdout, never stderr");
    Assert(!report.StandardOutput.Contains("SYNTHETIC_PRIVATE_SENTINEL"), "Secret from stderr leaked");
    Assert(!runner.IsRunning, "Runner remained active after result");
}

static async Task NonzeroExit()
{
    var runner = new WhiteAuditRunner();
    var output = await runner.RunAsync(Powershell("[Console]::Out.Write('{}'); exit 7"), TimeSpan.FromSeconds(15));
    Assert(output.ExitCode == 7, "Unexpected nonzero exit was normalized to success");
}

static async Task Cancellation()
{
    var runner = new WhiteAuditRunner();
    var running = runner.RunAsync(Powershell("Start-Sleep -Seconds 20"), TimeSpan.FromSeconds(30));
    int pid = await WaitForPid(runner);
    runner.Cancel();
    await Expect<OperationCanceledException>(running);
    await AssertExited(pid);
    Assert(!runner.IsRunning, "Runner remained busy after cancel");
}

static async Task Timeout()
{
    var runner = new WhiteAuditRunner();
    var running = runner.RunAsync(Powershell("Start-Sleep -Seconds 20"), TimeSpan.FromMilliseconds(700));
    int pid = await WaitForPid(runner);
    await Expect<TimeoutException>(running);
    await AssertExited(pid);
}

static async Task StdoutOverflow()
{
    var runner = new WhiteAuditRunner();
    await Expect<InvalidDataException>(runner.RunAsync(
        Powershell("[Console]::Out.Write(('A' * 20000))"),
        TimeSpan.FromSeconds(15), maxStdoutCharacters: 1024));
    Assert(!runner.IsRunning, "Runner still active after stdout overflow");
}

static async Task StderrOverflow()
{
    var runner = new WhiteAuditRunner();
    await Expect<InvalidDataException>(runner.RunAsync(
        Powershell("[Console]::Error.Write(('X' * 20000)); [Console]::Out.Write('{}')"),
        TimeSpan.FromSeconds(15), maxStderrCharacters: 1024));
    Assert(!runner.IsRunning, "Runner still active after stderr overflow");
}

static async Task PreventDuplicates()
{
    var runner = new WhiteAuditRunner();
    var running = runner.RunAsync(Powershell("Start-Sleep -Seconds 20"), TimeSpan.FromSeconds(30));
    int pid = await WaitForPid(runner);
    try
    {
        await Expect<InvalidOperationException>(runner.RunAsync(Powershell("[Console]::Out.Write('{}')"),
            TimeSpan.FromSeconds(10)));
    }
    finally
    {
        runner.Cancel();
        await Expect<OperationCanceledException>(running);
        await AssertExited(pid);
    }
}

static async Task RejectUnsafeConfiguration()
{
    var runner = new WhiteAuditRunner();
    var invalid = new ProcessStartInfo("powershell.exe") { UseShellExecute = true };
    await Expect<ArgumentException>(runner.RunAsync(invalid, TimeSpan.FromSeconds(10)));
    Assert(!runner.IsRunning, "Invalid configuration left runner busy");
}

static Task AtomicJsonExport()
{
    var root = Path.Combine(Path.GetTempPath(), "ots-report-test-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    try
    {
        var file = Path.Combine(root, "report.json");
        WhiteReportWriter.Save(file, "{\"complete\":true}");
        Assert(File.ReadAllText(file) == "{\"complete\":true}", "Valid JSON was not saved");
        try
        {
            WhiteReportWriter.Save(file, "NOT JSON");
            throw new Exception("Invalid report was accepted");
        }
        catch (System.Text.Json.JsonException) { }
        Assert(File.ReadAllText(file) == "{\"complete\":true}", "Invalid JSON overwrote the existing report");
        try
        {
            WhiteReportWriter.Save(file, "[]");
            throw new Exception("Non-object JSON was accepted");
        }
        catch (InvalidDataException) { }
        Assert(Directory.GetFiles(root).Length == 1, "Atomic export leaked a temporary file");
    }
    finally { Directory.Delete(root, recursive: true); }
    return Task.CompletedTask;
}

static Task ExportFailureCleanly()
{
    var root = Path.Combine(Path.GetTempPath(), "ots-report-test-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    try
    {
        var existing = Path.Combine(root, "existing.json");
        File.WriteAllText(existing, "{\"original\":true}");
        var absent = Path.Combine(root, "missing", "report.json");
        try
        {
            WhiteReportWriter.Save(absent, "{\"new\":true}");
            throw new Exception("Write into a missing directory was accepted");
        }
        catch (DirectoryNotFoundException) { }
        Assert(File.ReadAllText(existing) == "{\"original\":true}", "Failed export damaged other report");
        Assert(Directory.GetFiles(root).Length == 1, "Failed export leaked temporary output");
    }
    finally { Directory.Delete(root, recursive: true); }
    return Task.CompletedTask;
}

static Task BothQuarantineVaults()
{
    var baseDir = Path.Combine(Path.GetTempPath(), "ots-vault-registry-" + Guid.NewGuid().ToString("N"));
    var current = Path.Combine(baseDir, "current");
    var legacy = Path.Combine(baseDir, "legacy");
    Directory.CreateDirectory(baseDir);
    Directory.CreateDirectory(legacy);
    try
    {
        var oldFile = Path.Combine(baseDir, "legacy-fixture.pdf.exe");
        var newFile = Path.Combine(baseDir, "current-fixture.pdf.exe");
        File.WriteAllText(oldFile, "SYNTHETIC LEGACY DATA");
        File.WriteAllText(newFile, "SYNTHETIC CURRENT DATA");
        var oldService = new OTSSystemSanitizer.Core.QuarantineService(legacy);
        var oldRecord = oldService.Quarantine(oldFile);
        var vaults = new QuarantineVaultRegistry(current, legacy);
        var currentRecord = vaults.Quarantine(newFile);
        Assert(File.Exists(oldRecord.VaultFile) && File.Exists(currentRecord.VaultFile),
            "Creating a new vault corrupted a previous encrypted vault");
        Assert(vaults.List().Count == 2, "Did not show both current and historical quarantine records");
        Assert(currentRecord.VaultFile.StartsWith(current, StringComparison.OrdinalIgnoreCase),
            "New quarantine must be kept in the current OTS folder");
        vaults.Restore(oldRecord);
        Assert(File.ReadAllText(oldFile) == "SYNTHETIC LEGACY DATA",
            "Legacy DPAPI/AES vault did not round-trip through the unified UI registry");
        Assert(File.Exists(currentRecord.VaultFile), "Restoring legacy record affected current vault");
        vaults.Restore(currentRecord);
        Assert(File.ReadAllText(newFile) == "SYNTHETIC CURRENT DATA",
            "Current vault data could not be restored");
        Assert(vaults.List().Count == 0, "Restored files still appear in quarantine");
    }
    finally { Directory.Delete(baseDir, recursive: true); }
    return Task.CompletedTask;
}

static Task DoesNotCreateLegacyVault()
{
    var baseDir = Path.Combine(Path.GetTempPath(), "ots-vault-registry-" + Guid.NewGuid().ToString("N"));
    var current = Path.Combine(baseDir, "new");
    var missingLegacy = Path.Combine(baseDir, "old-not-present");
    try
    {
        var vaults = new QuarantineVaultRegistry(current, missingLegacy);
        Assert(Directory.Exists(current), "Current vault was not initialized");
        Assert(!Directory.Exists(missingLegacy), "Suite must not create a fake legacy vault");
        Assert(vaults.List().Count == 0, "Empty vault reports unexpected records");
    }
    finally { if (Directory.Exists(baseDir)) Directory.Delete(baseDir, recursive: true); }
    return Task.CompletedTask;
}

static async Task<int> WaitForPid(WhiteAuditRunner runner)
{
    for (int i = 0; i < 150; i++)
    {
        if (runner.ActiveProcessId is int pid) return pid;
        await Task.Delay(20);
    }
    throw new Exception("Process did not start in 3 seconds");
}

static async Task AssertExited(int pid)
{
    for (int i = 0; i < 100; i++)
    {
        try
        {
            using var child = Process.GetProcessById(pid);
            if (child.HasExited) return;
        }
        catch (ArgumentException) { return; }
        await Task.Delay(20);
    }
    throw new Exception("Child PID " + pid + " survived termination for over two seconds");
}

static async Task Expect<T>(Task action) where T : Exception
{
    try { await action; }
    catch (T) { return; }
    throw new Exception("Expected exception " + typeof(T).Name);
}

static void Assert(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}
