using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace OTSSecuritySuite.Desktop;

/// <summary>
/// Owns one untrusted CLI audit process at a time. The UI never receives raw stderr.
/// The caller controls whether an exit code/JSON report is considered exportable.
/// </summary>
public sealed class WhiteAuditRunner
{
    private readonly object _gate = new();
    private CancellationTokenSource? _activeCancellation;
    private Process? _activeProcess;
    private bool _running;

    public int? ActiveProcessId
    {
        get
        {
            lock (_gate)
            {
                try { return _activeProcess?.Id; }
                catch (InvalidOperationException) { return null; }
            }
        }
    }

    public bool IsRunning
    {
        get { lock (_gate) return _running; }
    }

    public void Cancel()
    {
        CancellationTokenSource? cancellation;
        Process? process;
        lock (_gate)
        {
            cancellation = _activeCancellation;
            process = _activeProcess;
        }

        try { cancellation?.Cancel(); }
        catch (ObjectDisposedException) { /* Run finished between lock and Cancel. */ }
        Terminate(process);
    }

    public async Task<WhiteAuditExecution> RunAsync(
        ProcessStartInfo startInfo,
        TimeSpan timeout,
        CancellationToken cancellationToken = default,
        int maxStdoutCharacters = 16 * 1024 * 1024,
        int maxStderrCharacters = 128 * 1024)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        if (!startInfo.RedirectStandardOutput || !startInfo.RedirectStandardError || startInfo.UseShellExecute)
            throw new ArgumentException("Audits must use redirected stdout/stderr without shell execution.", nameof(startInfo));
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromHours(1))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        if (maxStdoutCharacters <= 0 || maxStderrCharacters <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxStdoutCharacters));

        using var localCancellation = new CancellationTokenSource();
        lock (_gate)
        {
            if (_running) throw new InvalidOperationException("Another W.H.I.T.E. audit is running.");
            _running = true;
            _activeCancellation = localCancellation;
        }

        using var deadline = new CancellationTokenSource(timeout);
        using var combined = CancellationTokenSource.CreateLinkedTokenSource(
            localCancellation.Token, deadline.Token, cancellationToken);
        using var process = new Process { StartInfo = startInfo };

        try
        {
            combined.Token.ThrowIfCancellationRequested();
            if (!process.Start()) throw new InvalidOperationException("W.H.I.T.E. audit process failed to launch.");
            lock (_gate) _activeProcess = process;

            // On cancellation, timeout or host close, kill even if the CLI is not reading stdin.
            using var onCancel = combined.Token.Register(() => Terminate(process));
            var outputTask = ReadBoundedAsync(process.StandardOutput, process, maxStdoutCharacters, combined.Token);
            var errorTask = ReadBoundedAsync(process.StandardError, process, maxStderrCharacters, combined.Token);
            var exitTask = process.WaitForExitAsync(combined.Token);

            // Observe all three tasks; an overflowing pipe terminates the process so the other reads finish.
            await Task.WhenAll(outputTask, errorTask, exitTask).ConfigureAwait(false);
            combined.Token.ThrowIfCancellationRequested();
            return new WhiteAuditExecution(process.ExitCode, await outputTask.ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested
            && !localCancellation.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("W.H.I.T.E. audit reached its time limit.");
        }
        finally
        {
            Terminate(process);
            // Ensure the immediate child exits before exposing another audit; descendant checks are
            // a separate Windows acceptance requirement.
            try
            {
                if (process.HasExited == false)
                {
                    using var reapLimit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    await process.WaitForExitAsync(reapLimit.Token).ConfigureAwait(false);
                }
            }
            catch (InvalidOperationException) { /* Never launched or already disposed. */ }
            catch (OperationCanceledException) { /* OS did not terminate child within 5 seconds. */ }
            lock (_gate)
            {
                _activeProcess = null;
                _activeCancellation = null;
                _running = false;
            }
        }
    }

    private static async Task<string> ReadBoundedAsync(
        StreamReader reader, Process process, int maxCharacters, CancellationToken cancellation)
    {
        var text = new StringBuilder();
        var buffer = new char[8192];
        while (true)
        {
            int count = await reader.ReadAsync(buffer.AsMemory(), cancellation).ConfigureAwait(false);
            if (count == 0) return text.ToString();
            if (count > maxCharacters - text.Length)
            {
                Terminate(process);
                throw new InvalidDataException("Audit process exceeded its bounded output limit.");
            }
            text.Append(buffer, 0, count);
        }
    }

    private static void Terminate(Process? process)
    {
        if (process is null) return;
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException) { /* Process is not running. */ }
        catch (Win32Exception) { /* OS denied termination; checked by Windows acceptance tests. */ }
    }
}

public sealed record WhiteAuditExecution(int ExitCode, string StandardOutput);
