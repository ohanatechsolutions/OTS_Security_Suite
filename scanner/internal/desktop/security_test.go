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
