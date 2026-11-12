using System.IO;
using OTSSystemSanitizer.Core;

namespace OTSSecuritySuite.Desktop;

/// <summary>
/// Preserves and exposes BOTH the current Sanitizer and older Aegis Prime
/// vaults. Never migrates, decrypts, deletes or creates a legacy vault.
/// Operations are explicitly routed to the encrypted vault that owns a record.
/// </summary>
public sealed class QuarantineVaultRegistry
{
    private readonly QuarantineService _current;
    private readonly QuarantineService? _legacy;
    private readonly string _currentRoot;
    private readonly string? _legacyRoot;

    public QuarantineVaultRegistry(string? currentRoot = null, string? legacyRoot = null)
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        _currentRoot = Path.GetFullPath(currentRoot ?? Path.Combine(local, "OTSSystemSanitizer", "Quarantine"));
        var legacy = Path.GetFullPath(legacyRoot ?? Path.Combine(local, "AegisPrime", "Quarantine"));
        _current = new QuarantineService(_currentRoot);
        // Instantiating QuarantineService creates its directory, so never
        // instantiate the legacy service unless the old vault already exists.
        if (Directory.Exists(legacy) && !SamePath(_currentRoot, legacy))
        {
            _legacyRoot = legacy;
            _legacy = new QuarantineService(legacy);
        }
    }

    // Review authorization is scoped to one exact encrypted manifest identity
    // rather than an ID that could be reused across two historical vault roots.
    public static string ReviewIdentity(QuarantinedFile item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return item.Id + "|" + Path.GetFullPath(item.VaultFile).ToUpperInvariant()
             + "|" + item.Sha256.ToUpperInvariant();
    }

    public IReadOnlyList<QuarantinedFile> List()
    {
        var items = _current.List().ToList();
        if (_legacy is not null) items.AddRange(_legacy.List());
        return items.OrderByDescending(x => x.QuarantinedAt).ToArray();
    }

    public QuarantinedFile Quarantine(string original, string? investigation = null) =>
        _current.Quarantine(original, investigation);

    public void Restore(QuarantinedFile item) => SelectVault(item).Restore(item);
    public void Destroy(QuarantinedFile item) => SelectVault(item).Destroy(item);

    private QuarantineService SelectVault(QuarantinedFile item)
    {
        ArgumentNullException.ThrowIfNull(item);
        var parent = Path.GetDirectoryName(Path.GetFullPath(item.VaultFile));
        if (parent is not null && SamePath(parent, _currentRoot)) return _current;
        if (_legacy is not null && parent is not null && _legacyRoot is not null &&
            SamePath(parent, _legacyRoot)) return _legacy;
        throw new IOException("Quarantine item does not belong to an available OTS vault.");
    }

    private static bool SamePath(string left, string right) =>
        Path.TrimEndingDirectorySeparator(left).Equals(Path.TrimEndingDirectorySeparator(right),
            StringComparison.OrdinalIgnoreCase);
}
