using System.IO;
using System.Text;
using System.Text.Json;

namespace OTSSecuritySuite.Desktop;

/// <summary>
/// Commits an approved local W.H.I.T.E. JSON report without truncating an existing
/// destination when validation or writing fails. Caller owns file picker/overwrite consent.
/// </summary>
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
