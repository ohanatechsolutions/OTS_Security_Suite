package desktop

import (
	"context"
	"errors"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"ots/github-malware-scanner/internal/engine"
)

//go:embed assets/*
var assets embed.FS

const Addr = "127.0.0.1:48728"

var idPattern = regexp.MustCompile(`^\d{10,24}package desktop

import (
	"context"
	"errors"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"ots/github-malware-scanner/internal/engine"
)

//go:embed assets/*
var assets embed.FS

const Addr = "127.0.0.1:48728"

)

// History is local user-controlled data; never trust an on-disk JSON file's
// basename, claimed ID, type, or byte count without revalidation.
const maxStoredReportBytes int64 = 32 << 20

type Server struct {
	secret        string
	bindAddress   string
	actualAddress string
	reportsDir    string
	mu            sync.Mutex
	busy          bool
	lastHeartbeat time.Time
	heartbeatSeen bool
	web           *http.Server
}

func New() (*Server, error) {
	secretRaw := make([]byte, 24)
	if _, err := rand.Read(secretRaw); err != nil {
		return nil, err
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(d, "Ohana Tech Solutions", "GitHub Malware Scanner", "reports")
	if err = os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	return &Server{secret: hex.EncodeToString(secretRaw), reportsDir: path, bindAddress: Addr}, nil
}
func (s *Server) UseEphemeralPort() { s.bindAddress = "127.0.0.1:0" }

func (s *Server) Start() (string, error) {
	listener, err := net.Listen("tcp", s.bindAddress)
	if err != nil {
		return "", fmt.Errorf("cannot open local scanner on %s: %w", s.bindAddress, err)
	}
	s.actualAddress = listener.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.page)
	mux.HandleFunc("/styles.css", s.static)
	mux.HandleFunc("/app.js", s.static)
	mux.HandleFunc("/favicon.png", s.static)
	mux.HandleFunc("/ohana-logo.png", s.static)
	mux.HandleFunc("/manifest.webmanifest", s.static)
	mux.HandleFunc("/app-icon-192.png", s.static)
	mux.HandleFunc("/app-icon-512.png", s.static)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true,"product":"OTS GitHub Malware Scanner"}`))
	})
	mux.HandleFunc("/api/info", s.withAuth(s.info))
	mux.HandleFunc("/api/scan", s.withAuth(s.scan))
	mux.HandleFunc("/api/scan-upload", s.withAuth(s.scanUpload))
	mux.HandleFunc("/api/history", s.withAuth(s.history))
	mux.HandleFunc("/api/report/", s.withAuth(s.report))
	mux.HandleFunc("/api/quit", s.withAuth(s.quit))
	mux.HandleFunc("/api/window-heartbeat", s.withAuth(s.windowHeartbeat))
	s.web = &http.Server{
		ReadHeaderTimeout: 8 * time.Second,
		ReadTimeout: 120 * time.Second,
		WriteTimeout: 180 * time.Second,
		IdleTimeout: 25 * time.Second,
		MaxHeaderBytes: 1 << 20,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != s.actualAddress {
			http.Error(w, "invalid host", 403)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'")
		mux.ServeHTTP(w, r)
	})}
	go s.web.Serve(listener)
	return "http://" + s.actualAddress + "/?t=" + s.secret, nil
}
func (s *Server) authenticated(r *http.Request) bool {
	c, err := r.Cookie("ots_session")
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.secret)) == 1
}
func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	t := r.URL.Query().Get("t")
	if t != "" && subtle.ConstantTimeCompare([]byte(t), []byte(s.secret)) == 1 {
		http.SetCookie(w, &http.Cookie{Name: "ots_session", Value: s.secret, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 86400})
		u := *r.URL
		q := u.Query()
		q.Del("t")
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
		return
	}
	if !s.authenticated(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("<h2>OTS GitHub Malware Scanner is locked.</h2><p>Launch the installed desktop application to sign in locally.</p>"))
		return
	}
	b, err := assets.ReadFile("assets/index.html")
	if err != nil {
		http.Error(w, "UI unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}
func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	if !s.authenticated(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	var file, mime string
	if r.URL.Path == "/favicon.png" {
		file = "assets/favicon.png"
		mime = "image/png"
	} else if r.URL.Path == "/ohana-logo.png" {
		file = "assets/ohana-logo.png"
		mime = "image/png"
	} else if r.URL.Path == "/app-icon-192.png" {
		file = "assets/app-icon-192.png"
		mime = "image/png"
	} else if r.URL.Path == "/app-icon-512.png" {
		file = "assets/app-icon-512.png"
		mime = "image/png"
	} else if r.URL.Path == "/manifest.webmanifest" {
		file = "assets/manifest.webmanifest"
		mime = "application/manifest+json; charset=utf-8"
	} else if r.URL.Path == "/app.js" {
		file = "assets/app.js"
		mime = "text/javascript; charset=utf-8"
	} else {
		file = "assets/styles.css"
		mime = "text/css; charset=utf-8"
	}
	b, err := assets.ReadFile(file)
	if err != nil {
		http.Error(w, "missing asset", 500)
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}
func (s *Server) withAuth(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticated(r) {
			http.Error(w, "unauthorized - launch desktop application", 401)
			return
		}
		if r.Method != "GET" && r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		if r.Method == "POST" && r.Header.Get("Origin") != "http://"+s.actualAddress {
			http.Error(w, "origin rejected", 403)
			return
		}
		fn(w, r)
	}
}
func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(data)
}
func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"version": "2.5.0", "publisher": "Ohana Tech Solutions", "rule_count": engine.RulesCount(), "offline": true, "folder_reports": s.reportsDir})
}
func (s *Server) busyStart() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy {
		return false
	}
	s.busy = true
	return true
}
func (s *Server) busyEnd() { s.mu.Lock(); s.busy = false; s.mu.Unlock() }
func (s *Server) save(report *engine.Report) error {
	// An invalid ID must never control a report path.
	if report == nil || !idPattern.MatchString(report.ID) {
		return errors.New("invalid report identifier")
	}
	data, err := engine.ReportJSON(report)
	if err != nil { return err }
	tmp, err := os.CreateTemp(s.reportsDir, ".ots-report-*.tmp")
	if err != nil { return err }
	stage := tmp.Name()
	defer os.Remove(stage)
	if err = tmp.Chmod(0600); err != nil { tmp.Close(); return err }
	if _, err = tmp.Write(data); err != nil { tmp.Close(); return err }
	if err = tmp.Sync(); err != nil { tmp.Close(); return err }
	if err = tmp.Close(); err != nil { return err }
	// A complete report becomes visible to history and export together.
	return os.Rename(stage, filepath.Join(s.reportsDir, report.ID+".json"))
}
func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}
	if !s.busyStart() {
		http.Error(w, "another scan is in progress", 409)
		return
	}
	defer s.busyEnd()
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	var req struct {
		URL    string `json:"url"`
		Folder string `json:"folder"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid input", 400)
		return
	}
	var report *engine.Report
	var err error
	if strings.TrimSpace(req.URL) != "" {
		report, err = engine.ScanRemoteContext(r.Context(), req.URL)
	} else if strings.TrimSpace(req.Folder) != "" {
		report, err = engine.ScanDirContext(r.Context(), req.Folder)
	} else {
		http.Error(w, "specify URL or folder", 400)
		return
	}
	if err != nil {
		// The originating UI may already have disconnected. Never persist a
		// partial/cancelled scan as a successful report.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) { return }
		http.Error(w, err.Error(), 400)
		return
	}
	if r.Context().Err() != nil { return }
	if r.Context().Err() != nil { return }
	if err := s.save(report); err != nil {
		http.Error(w, "Could not save local scan report. Check available disk space and folder permissions.", http.StatusInsufficientStorage)
		return
	}
	writeJSON(w, report)
}
func (s *Server) scanUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}
	if !s.busyStart() {
		http.Error(w, "another scan is in progress", 409)
		return
	}
	defer s.busyEnd()
	r.Body = http.MaxBytesReader(w, r.Body, 240<<20)
	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "expected multipart folder upload", 400)
		return
	}
	report := engine.NewReport("Browser-selected local folder", "local folder (browser upload)")
	count := 0
	for {
		if r.Context().Err() != nil { return }
		part, e := reader.NextPart()
		if e == io.EOF {
			break
		}
		if e != nil {
			http.Error(w, "upload parse error", 400)
			return
		}
		if part.FormName() != "files" {
			part.Close()
			continue
		}
		count++
		if count > engine.MaxFiles {
			report.Truncated = true
			part.Close()
			break
		}
		name := filepath.ToSlash(part.FileName())
		if name == "" {
			name = fmt.Sprintf("selected-file-%d", count)
		}
		data, e := io.ReadAll(io.LimitReader(part, engine.MaxFileBytes+1))
		part.Close()
		if e != nil {
			http.Error(w, "folder upload read error", 400)
			return
		}
		if r.Context().Err() != nil { return }
		engine.ScanBytes(report, name, data)
	}
	if r.Context().Err() != nil { return }
	engine.Finalize(report)
	if r.Context().Err() != nil { return }
	if err := s.save(report); err != nil {
		http.Error(w, "Could not save local scan report. Check available disk space and folder permissions.", http.StatusInsufficientStorage)
		return
	}
	writeJSON(w, report)
}
func (s *Server) readStoredReport(id string) ([]byte, *engine.Report, error) {
	if !idPattern.MatchString(id) {
		return nil, nil, errors.New("invalid report identifier")
	}
	filename := filepath.Join(s.reportsDir, id+".json")
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxStoredReportBytes {
		return nil, nil, errors.New("invalid report file type or size")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxStoredReportBytes+1))
	if err != nil || int64(len(data)) > maxStoredReportBytes {
		return nil, nil, errors.New("report exceeds storage read limit")
	}
	var parsed engine.Report
	if json.Unmarshal(data, &parsed) != nil || parsed.ID != id ||
		parsed.ID == "" || parsed.RulesAvailable < 0 {
		return nil, nil, errors.New("local report metadata does not match filename")
	}
	return data, &parsed, nil
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "GET required", 405)
		return
	}
	entries, err := os.ReadDir(s.reportsDir)
	if err != nil {
		http.Error(w, "history unavailable", 500)
		return
	}
	type summary struct {
		ID      string `json:"id"`
		Target  string `json:"target"`
		Date    string `json:"date"`
		Score   int    `json:"score"`
		Verdict string `json:"verdict"`
		Count   int    `json:"count"`
	}
	out := []summary{}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() > entries[j].Name() })
	for _, e := range entries {
		if len(out) >= 75 {
			break
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if !idPattern.MatchString(id) {
			continue
		}
		_, item, err := s.readStoredReport(id)
		if err != nil { continue }
		out = append(out, summary{item.ID, item.Target, item.Date, item.Score, item.Verdict, len(item.Findings)})
	}
	writeJSON(w, out)
}
func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "GET required", 405)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/report/")
	if !idPattern.MatchString(id) {
		http.Error(w, "invalid report ID", 400)
		return
	}
	b, _, err := s.readStoredReport(id)
	if err != nil {
		http.Error(w, "report missing or invalid", 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=OTS-Scan-%s.json", id))
	}
	w.Write(b)
}
func (s *Server) quit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}
	writeJSON(w, map[string]bool{"closing": true})
	go func() { time.Sleep(300 * time.Millisecond); s.web.Close(); os.Exit(0) }()
}

// windowHeartbeat records the presence of the UI without accepting any user data.
func (s *Server) windowHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	s.lastHeartbeat = time.Now()
	s.heartbeatSeen = true
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// WindowExpired checks both the startup grace period and activity liveness.
// It is called only by the standalone desktop process, not by the test server.
func (s *Server) WindowExpired(started time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.heartbeatSeen {
		return time.Since(started) > 30*time.Second
	}
	return time.Since(s.lastHeartbeat) > 6*time.Second
}
