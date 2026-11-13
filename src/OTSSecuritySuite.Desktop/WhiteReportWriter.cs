using System.IO;
using System.Text;
using System.Text.Json;

namespace OTSSecuritySuite.Desktop;

/// <summary>
/// Commits an approved local W.H.I.T.E. JSON report without truncating an existing
/// destination when validation or writing fails. Caller owns file picker/overwrite consent.
/// </summary>
public sealed record WhiteReportAssessment(bool Complete, int FindingCount);

public static class WhiteAuditReportValidator
{
    /// <summary>
    /// Never infer clean/complete status solely from a child-process exit code.
    /// An inconsistent schema or mismatched report is rejected before UI export.
    /// </summary>
    public static WhiteReportAssessment Assess(string json, int exitCode)
    {
        if (exitCode is not (0 or 1 or 2))
            throw new InvalidDataException("Audit process returned an unrecognized status.");
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("tool", out var tool) ||
            tool.ValueKind != JsonValueKind.String || tool.GetString() != "OTS W.H.I.T.E." ||
            !root.TryGetProperty("schema_version", out var version) ||
            version.ValueKind != JsonValueKind.String || version.GetString() != "1.0" ||
            !root.TryGetProperty("complete", out var complete) ||
            complete.ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
            !root.TryGetProperty("checks", out var checks) || checks.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("errors", out var errors) || errors.ValueKind != JsonValueKind.Array ||
            !root.TryGetProperty("findings", out var findings) || findings.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Audit output does not match the supported W.H.I.T.E. JSON schema.");

        bool checksComplete = true;
        foreach (var check in checks.EnumerateObject())
        {
            if (check.Value.ValueKind != JsonValueKind.String ||
                check.Value.GetString() is not ("completed" or "skipped"))
                checksComplete = false;
        }
        // A report with source-level failures, incomplete checks, or exit=2
        // remains incomplete even when a child erroneously declares complete.
        bool isComplete = complete.GetBoolean() && checksComplete &&
                          errors.GetArrayLength() == 0 && exitCode != 2;
        return new WhiteReportAssessment(isComplete, findings.GetArrayLength());
    }
}

/// <summary>
/// Read a user-selected local JSON report without trusting it as scan evidence.
/// No network calls, execution, implicit export, or file modifications.
/// </summary>
public sealed record WhiteImportedReport(string Json, WhiteReportAssessment Assessment);

public static class WhiteReportReader
{
    public const int MaxReportBytes = 16 << 20;

    public static WhiteImportedReport Read(string selectedPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(selectedPath);
        using var source = new FileStream(selectedPath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 8192, FileOptions.SequentialScan);
        if (source.Length > MaxReportBytes)
            throw new InvalidDataException("Imported report exceeds the 16 MiB safe limit.");
        var bytes = new byte[checked((int)source.Length)];
        source.ReadExactly(bytes);
        if (source.ReadByte() != -1)
            throw new InvalidDataException("Imported report changed while being read.");
        var json = new UTF8Encoding(false, throwOnInvalidBytes: true)
            .GetString(bytes).TrimStart('\uFEFF');
        var assessment = WhiteAuditReportValidator.Assess(json, 0);
        return new WhiteImportedReport(json, assessment);
    }
}

public static class WhiteReportWriter
{
    public static void Save(string selectedPath, string jsonReport)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(selectedPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(jsonReport);
        if (jsonReport.Length > 16 * 1024 * 1024)
            throw new InvalidDataException("Audit report exceeds the safe export size.");

        // Validate before opening any filesystem destination.
        using (var document = JsonDocument.Parse(jsonReport))
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("Audit report must be a JSON object.");
        }

        var destination = Path.GetFullPath(selectedPath);
        var parent = Path.GetDirectoryName(destination)
            ?? throw new InvalidOperationException("Report destination has no parent folder.");
        if (!Directory.Exists(parent))
            throw new DirectoryNotFoundException("Selected report folder does not exist.");

        // Same-volume atomic rename: old report stays untouched until the new
        // temporary file is fully written and flushed.
        var tempPath = Path.Combine(parent, ".ots-report-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 8192, FileOptions.WriteThrough))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(false), 8192, leaveOpen: true))
            {
                writer.Write(jsonReport);
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }

            File.Move(tempPath, destination, overwrite: true);
        }
        finally
        {
            // A failed write or destination denial must not leave an untracked
            // partial JSON report. Failure cleanup is best effort only.
            try { if (File.Exists(tempPath)) File.Delete(tempPath); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
