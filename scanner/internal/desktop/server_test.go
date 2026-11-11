package desktop

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ots/github-malware-scanner/internal/engine"
)

func TestLocalServerSessionScanAndHistory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	rawURL, err := s.Start()
	if err != nil {
		t.Skipf("local port unavailable: %v", err)
	}
	defer s.web.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	unauth, err := http.Get("http://" + Addr + "/api/info")
	if err != nil {
		t.Fatal(err)
	}
	unauth.Body.Close()
	if unauth.StatusCode != 401 {
		t.Errorf("unauth status: %v", unauth.StatusCode)
	}
	page, err := client.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	content, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if page.StatusCode != 200 || !strings.Contains(string(content), "GitHub Malware Scanner") {
		t.Fatalf("bad desktop page: %v %s", page.StatusCode, content)
	}
	for _, asset := range []struct{ path, mime string }{
		{"/ohana-logo.png", "image/png"},
		{"/favicon.png", "image/png"},
		{"/app-icon-192.png", "image/png"},
		{"/manifest.webmanifest", "application/manifest+json"},
	} {
		res, err := client.Get("http://" + Addr + asset.path)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), asset.mime) {
			t.Fatalf("bad branding asset %s: status=%d contentType=%s", asset.path, res.StatusCode, res.Header.Get("Content-Type"))
		}
		if asset.mime == "image/png" && (len(data) < 8 || string(data[1:4]) != "PNG") {
			t.Fatalf("branding asset %s is not PNG data", asset.path)
		}
	}
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "package.json"), []byte(`{"scripts":{"postinstall":"node setup.js"}}`), 0600)
	input, _ := json.Marshal(map[string]string{"folder": tmp})
	req, _ := http.NewRequest("POST", "http://"+Addr+"/api/scan", strings.NewReader(string(input)))
	req.Header.Set("Origin", "http://"+Addr)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("scan error: %v %s", resp.StatusCode, b)
	}
	var report engine.Report
	if err = json.NewDecoder(resp.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	if report.Score == 0 || report.FilesScanned != 1 {
		t.Fatalf("unexpected report %+v", report)
	}
	history, err := client.Get("http://" + Addr + "/api/history")
	if err != nil {
		t.Fatal(err)
	}
	defer history.Body.Close()
	var items []any
	if err = json.NewDecoder(history.Body).Decode(&items); err != nil || len(items) != 1 {
		t.Fatalf("history %v %v", items, err)
	}
}
