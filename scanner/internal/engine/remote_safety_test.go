package engine

import (
    "archive/tar"
    "bytes"
    "compress/gzip"
    "strings"
    "testing"
)

func TestRemoteArchiveNormalScan(t *testing.T) {
    var tarData bytes.Buffer
    tarWriter := tar.NewWriter(&tarData)
    files := map[string]string{
        "snapshot/README.md": "This repository is a benign fixture.\n",
        "snapshot/src/hello.py": "print('hello world')\n",
    }
    for name, data := range files {
        if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}); err != nil {
            t.Fatal(err)
        }
        if _, err := tarWriter.Write([]byte(data)); err != nil { t.Fatal(err) }
    }
    if err := tarWriter.Close(); err != nil { t.Fatal(err) }
    var compressed bytes.Buffer
    gz := gzip.NewWriter(&compressed)
    if _, err := gz.Write(tarData.Bytes()); err != nil { t.Fatal(err) }
    if err := gz.Close(); err != nil { t.Fatal(err) }

    report := NewReport("fixture", "test")
    if err := scanRemoteArchive(&compressed, report); err != nil { t.Fatal(err) }
    if report.FilesSeen != len(files) || report.FilesScanned != len(files) ||
        report.FilesSkipped != 0 || report.Truncated {
        t.Fatalf("ordinary remote snapshot coverage unexpected: seen=%d scanned=%d skipped=%d truncated=%t",
            report.FilesSeen, report.FilesScanned, report.FilesSkipped, report.Truncated)
    }
}

func TestRemoteArchiveRejectsBombSizedDeclaredEntryWithoutExpandingIt(t *testing.T) {
    // A valid TAR header declares a >192 MiB file, but deliberately omits its
    // body. The decompression guard must stop at the header before reading data.
    var headerOnly bytes.Buffer
    writer := tar.NewWriter(&headerOnly)
    if err := writer.WriteHeader(&tar.Header{
        Name: "snapshot/huge.bin",
        Mode: 0600,
        Size: MaxRemoteUnpackedBytes + 1,
    }); err != nil {
        t.Fatal(err)
    }
    // Do not close the incomplete TAR writer: that would require writing >192 MiB.
    var compressed bytes.Buffer
    gz := gzip.NewWriter(&compressed)
    if _, err := gz.Write(headerOnly.Bytes()); err != nil { t.Fatal(err) }
    if err := gz.Close(); err != nil { t.Fatal(err) }

    report := NewReport("fixture", "test")
    if err := scanRemoteArchive(&compressed, report); err != nil { t.Fatal(err) }
    if !report.Truncated || report.FilesSeen != 1 || report.FilesSkipped != 1 ||
        report.Verdict != "INCOMPLETE ANALYSIS" {
        t.Fatalf("remote compressed bomb header was misreported as complete: %+v", report)
    }
    if len(report.Coverage) != 1 || !strings.Contains(report.Coverage[0].Reason, "decompression") {
        t.Fatalf("remote skip reason missing: %+v", report.Coverage)
    }
}

func TestRemoteArchiveRejectsMalformedCompressedInput(t *testing.T) {
    report := NewReport("fixture", "test")
    if err := scanRemoteArchive(strings.NewReader("not gzip or tar"), report); err == nil {
        t.Fatal("malformed archive accepted as valid")
    }
}

func TestRootRepoURLsRejectAmbiguousPaths(t *testing.T) {
    for _, input := range []string{
        "https://github.com/example/sample/tree/main",
        "https://github.com/example/sample?ref=private",
        "https://github.com/example/sample#readme",
        "https://github.com/example/sample/issues/1",
        "https://github.com/example/sample/../../admin",
        "https://github.com@example.invalid/example/sample",
    } {
        if _, _, _, err := ParseRepo(input); err == nil {
            t.Errorf("accepted ambiguous repository URL %q", input)
        }
    }
    if h, o, p, err := ParseRepo("https://github.com/example/sample.git"); err != nil ||
        h != "github.com" || o != "example" || p != "sample" {
        t.Fatalf("root URL rejected: %s/%s/%s error=%v", h, o, p, err)
    }
}
