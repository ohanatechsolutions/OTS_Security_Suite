using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace OTSSecuritySuite.Desktop;

/// <summary>
/// One application instance per Windows user/session. Secondary invocations
/// forward a bounded protocol URI through a same-user named pipe; the broker
/// never grants remote authority or executes received commands.
/// </summary>
public sealed class ProtocolActivation : IDisposable
{
    public const int MaxProtocolBytes = 4096;
    private readonly string _mutexName;
    private readonly string _pipeName;
    private readonly CancellationTokenSource _stop = new();
    private Mutex? _lifetimeMutex;
    private Task? _listener;
    private bool _isPrimary;
    private bool _disposed;

    public ProtocolActivation(string? testScope = null)
    {
        var sid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("Windows user identity is unavailable.");
        var sessionId = Environment.ProcessId > 0
            ? System.Diagnostics.Process.GetCurrentProcess().SessionId : 0;
        var suffix = testScope is null ? "" : "." + Regex.Replace(testScope, "[^A-Za-z0-9_-]", "");
        var name = "OTS.SecuritySuite." + sid + "." + sessionId + suffix;
        _mutexName = @"Local\" + name;
        _pipeName = name;
    }

    public bool TryBecomePrimary()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_lifetimeMutex is not null) throw new InvalidOperationException("Already initialized.");
        // Existence, not mutex ownership, is the lifetime lock. Its handle
        // lasts until this app exits even when async work changes threads.
        _lifetimeMutex = new Mutex(false, _mutexName, out var createdNew);
        if (!createdNew)
        {
            _lifetimeMutex.Dispose();
            _lifetimeMutex = null;
            return false;
        }
        _isPrimary = true;
        return true;
    }

    public void StartListening(Action<string> onMessage)
    {
        ArgumentNullException.ThrowIfNull(onMessage);
        if (!_isPrimary || _listener is not null) throw new InvalidOperationException("Primary instance required.");
        _listener = Task.Run(async () =>
        {
            while (!_stop.IsCancellationRequested)
            {
                try
                {
                    using var pipe = new NamedPipeServerStream(
                        _pipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                    await pipe.WaitForConnectionAsync(_stop.Token).ConfigureAwait(false);
                    var header = new byte[4];
                    await pipe.ReadExactlyAsync(header, _stop.Token).ConfigureAwait(false);
                    var count = BinaryPrimitives.ReadInt32LittleEndian(header);
                    if (count <= 0 || count > MaxProtocolBytes) continue;
                    var payload = new byte[count];
                    await pipe.ReadExactlyAsync(payload, _stop.Token).ConfigureAwait(false);
                    string uri = new UTF8Encoding(false, true).GetString(payload);
                    if (TrustedProtocol.TryParse(uri, out _)) onMessage(uri);
                }
                catch (OperationCanceledException) when (_stop.IsCancellationRequested) { break; }
                catch (IOException) { /* Disconnected secondary invocation; accept next. */ }
                catch (DecoderFallbackException) { /* Reject invalid UTF-8. */ }
                catch (UnauthorizedAccessException) { /* Refuse another user's session. */ }
            }
        });
    }

    public async Task<bool> SendToPrimaryAsync(string uri, CancellationToken cancellationToken = default)
    {
        if (!TrustedProtocol.TryParse(uri, out _)) return false;
        var bytes = Encoding.UTF8.GetBytes(uri);
        if (bytes.Length > MaxProtocolBytes) return false;
        for (var i = 0; i < 20; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var client = new NamedPipeClientStream(".", _pipeName,
                PipeDirection.Out, PipeOptions.Asynchronous);
            try
            {
                await client.ConnectAsync(150, cancellationToken).ConfigureAwait(false);
                var header = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(header, bytes.Length);
                await client.WriteAsync(header, cancellationToken).ConfigureAwait(false);
                await client.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await client.FlushAsync(cancellationToken).ConfigureAwait(false);
                return true;
            }
            catch (TimeoutException) { /* Primary may still be starting. */ }
            catch (IOException) { /* Primary pipe may be reconnecting. */ }
            catch (UnauthorizedAccessException) { return false; }
            await Task.Delay(100, cancellationToken).ConfigureAwait(false);
        }
        return false;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _stop.Cancel();
        _lifetimeMutex?.Dispose();
        _stop.Dispose();
    }
}

/// <summary>Accepts only the suite's public root-repository custom protocol.</summary>
public static class TrustedProtocol
{
    private static readonly Regex RepoSegment = new(@"^[a-zA-Z0-9_.-]{1,100}$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static bool TryParse(string? incoming, out string? repository)
    {
        repository = null;
        if (string.IsNullOrWhiteSpace(incoming) || incoming.Length > 4096 ||
            !Uri.TryCreate(incoming, UriKind.Absolute, out var uri) ||
            uri.Scheme != "ots-security" || uri.Host != "scan" ||
            !uri.IsDefaultPort || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 ||
            uri.AbsolutePath is not ("" or "/"))
            return false;
        if (uri.Query.Length == 0) return true; // Activate the existing window.
        if (!uri.Query.StartsWith("?url=", StringComparison.OrdinalIgnoreCase))
            return false;
        var unescaped = Uri.UnescapeDataString(uri.Query[5..]);
        return TryNormalizeRepository(unescaped, out repository);
    }

    public static bool TryNormalizeRepository(string? input, out string? repository)
    {
        repository = null;
        if (string.IsNullOrWhiteSpace(input) || input.Length > 2048 ||
            !Uri.TryCreate(input, UriKind.Absolute, out var url) ||
            url.Scheme != "https" || !url.IsDefaultPort || url.UserInfo.Length != 0 ||
            url.Fragment.Length != 0 || url.Query.Length != 0)
            return false;
        var host = url.Host.ToLowerInvariant();
        if (host == "www.github.com") host = "github.com";
        if (host is not ("github.com" or "bitbucket.org")) return false;
        var parts = url.AbsolutePath.Trim('/').Split('/');
        if (parts.Length != 2 || !RepoSegment.IsMatch(parts[0])) return false;
        var repoName = parts[1].EndsWith(".git", StringComparison.OrdinalIgnoreCase)
            ? parts[1][..^4] : parts[1];
        if (!RepoSegment.IsMatch(repoName) ||
            parts[0] is "." or ".." || repoName is "." or ".." ||
            parts[0].Contains("..", StringComparison.Ordinal) ||
            repoName.Contains("..", StringComparison.Ordinal))
            return false;
        repository = "https://" + host + "/" + parts[0] + "/" + repoName;
        return true;
    }
}
