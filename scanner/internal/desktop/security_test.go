package desktop

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ots/github-malware-scanner/internal/engine"
)

func newSecurityFixture(t *testing.T) *Server {
	t.Helper()
	return &Server{
		secret:        strings.Repeat("a", 48),
		actualAddress: "127.0.0.1:54321",
		reportsDir:    t.TempDir(),
	}
}

func requestWithCookie(method, url, body, secret, origin string) *http.Request {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	if secret != "" {
		req.AddCookie(&http.Cookie{Name: "ots_session", Value: secret})
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return req
}

func TestApiRejectsUnauthorizedAndCrossOriginWrites(t *testing.T) {
	s := newSecurityFixture(t)
	cases := []struct {
		name, method, token, origin string
		want int
	}{
		{"unauthorized scan", "POST", "", "http://" + "127.0.0.1:54321", 401},
		{"bad session", "POST", "wrong", "http://" + "127.0.0.1:54321", 401},
		{"cross site", "POST", s.secret, "https://malicious.example", 403},
		{"no origin", "POST", s.secret, "", 403},
		{"localhost alias", "POST", s.secret, "http://localhost:54321", 403},
		{"different port", "POST", s.secret, "http://127.0.0.1:54322", 403},
		{"disallowed method", "PUT", s.secret, "", 405},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := requestWithCookie(tc.method,
				"http://127.0.0.1:54321/api/scan", `{"folder":"ignored"}`,
				tc.token, tc.origin)
			recorder := httptest.NewRecorder()
			s.withAuth(s.scan)(recorder, req)
			if recorder.Code != tc.want {
				t.Fatalf("expected HTTP %d, got %d", tc.want, recorder.Code)
			}
		})
	}
	items, err := os.ReadDir(s.reportsDir)
	if err != nil || len(items) != 0 {
		t.Fatalf("denied requests wrote reports: files=%d err=%v", len(items), err)
	}
}

func TestCancelledLocalHttpScanDoesNotPersistReport(t *testing.T) {
	s := newSecurityFixture(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "fixture.py"), []byte("print('safe')"), 0600); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"folder": root})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := requestWithCookie("POST", "http://127.0.0.1:54321/api/scan",
		string(body), s.secret, "http://127.0.0.1:54321").WithContext(ctx)
	recorder := httptest.NewRecorder()
	s.withAuth(s.scan)(recorder, req)
	items, err := os.ReadDir(s.reportsDir)
	if err != nil || len(items) != 0 {
		t.Fatalf("cancelled request saved an apparently complete report: files=%d err=%v", len(items), err)
	}
	if s.busy {
		t.Fatal("cancellation left the server busy and blocked future scans")
	}
}

func TestServerEnforcesConnectionLimits(t *testing.T) {
	s, err := New()
	if err != nil { t.Fatal(err) }
	s.UseEphemeralPort()
	_, err = s.Start()
	if err != nil { t.Fatal(err) }
	defer s.web.Close()
	if s.web.ReadHeaderTimeout < 3*time.Second ||
		s.web.IdleTimeout <= 0 || s.web.ReadTimeout <= 0 ||
		s.web.WriteTimeout <= 0 || s.web.MaxHeaderBytes > 1<<20 {
		t.Fatalf("unsafe unbounded HTTP server limits: %+v", s.web)
	}
}

// File errors must not return an apparently successful scan whose export
// endpoint and history would later fail.
func TestFailedReportPersistenceFailsClosed(t *testing.T) {
	s := newSecurityFixture(t)
	s.reportsDir = filepath.Join(t.TempDir(), "missing-folder")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "benign.py"), []byte("print('fixture')"), 0600); err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]string{"folder": root})
	req := requestWithCookie(http.MethodPost,
		"http://127.0.0.1:54321/api/scan", string(input), s.secret, "http://127.0.0.1:54321")
	response := httptest.NewRecorder()
	s.withAuth(s.scan)(response, req)
	if response.Code != http.StatusInsufficientStorage {
		t.Fatalf("expected HTTP 507 storage error, got %d %s", response.Code, response.Body.String())
	}
	if s.busy { t.Fatal("failed report persistence left scanner permanently busy") }
	if strings.Contains(response.Body.String(), root) {
		t.Fatal("error body leaked local source directory")
	}
}

func TestSavedReportAtomicAndRejectsUnsafeIdentifiers(t *testing.T) {
	s := newSecurityFixture(t)
	record := engine.NewReport("synthetic-only", "local fixture")
	if err := s.save(record); err != nil { t.Fatal(err) }
	files, err := os.ReadDir(s.reportsDir)
	if err != nil || len(files) != 1 || files[0].Name() != record.ID+".json" {
		t.Fatalf("atomic save left temp/unexpected files: %v %v", files, err)
	}
	data, err := os.ReadFile(filepath.Join(s.reportsDir, record.ID+".json"))
	if err != nil { t.Fatal(err) }
	var parsed engine.Report
	if err := json.Unmarshal(data, &parsed); err != nil || parsed.ID != record.ID {
		t.Fatalf("invalid stored JSON: %v", err)
	}
	record.ID = "../escape"
	if err := s.save(record); err == nil { t.Fatal("unsafe report identifier was accepted") }
	files, err = os.ReadDir(s.reportsDir)
	if err != nil || len(files) != 1 { t.Fatalf("failed save modified history: %v %v", files, err) }
}

func TestHistorySkipsForgedOrOversizedLocalReports(t *testing.T) {
	s := newSecurityFixture(t)
	good := engine.NewReport("safe synthetic", "local test")
	if err := s.save(good); err != nil { t.Fatal(err) }
	forgedID := "1712345678900000001"
	bad, err := engine.ReportJSON(good)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(s.reportsDir, forgedID+".json"), bad, 0600); err != nil { t.Fatal(err) }
	oversizedID := "1712345678900000002"
	large, err := os.Create(filepath.Join(s.reportsDir, oversizedID+".json"))
	if err != nil { t.Fatal(err) }
	if err := large.Truncate(maxStoredReportBytes+1); err != nil { large.Close(); t.Fatal(err) }
	large.Close()
	malformedID := "1712345678900000003"
	if err := os.WriteFile(filepath.Join(s.reportsDir, malformedID+".json"), []byte("{"), 0600); err != nil { t.Fatal(err) }

	request := requestWithCookie("GET","http://127.0.0.1:54321/api/history","",s.secret,"")
	result := httptest.NewRecorder()
	s.withAuth(s.history)(result,request)
	if result.Code != 200 { t.Fatalf("history returned %d",result.Code) }
	var rows []struct{ ID string `json:"id"` }
	if err := json.Unmarshal(result.Body.Bytes(), &rows); err != nil { t.Fatal(err) }
	if len(rows) != 1 || rows[0].ID != good.ID {
		t.Fatalf("history should hide forged, malformed and oversize files: %+v",rows)
	}
	for _, id := range []string{forgedID,oversizedID,malformedID} {
		rec := httptest.NewRecorder()
		req := requestWithCookie("GET","http://127.0.0.1:54321/api/report/"+id,"",s.secret,"")
		s.withAuth(s.report)(rec,req)
		if rec.Code != 404 {
			t.Fatalf("invalid report %s was downloadable: HTTP %d",id,rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	req := requestWithCookie("GET","http://127.0.0.1:54321/api/report/"+good.ID,"",s.secret,"")
	s.withAuth(s.report)(rec,req)
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("valid report not served privately and without caching")
	}
}
