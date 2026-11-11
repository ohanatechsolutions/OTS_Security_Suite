package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"ots/github-malware-scanner/internal/desktop"
)

func main() {
	s, err := desktop.New()
	if err != nil {
		showErrorDialog(err.Error())
		return
	}
	if hasArg("--ephemeral") {
		s.UseEphemeralPort()
	}
	addr, err := s.Start()
	if err != nil {
		showErrorDialog(err.Error())
		return
	}
	if hasArg("--print-url") {
		fmt.Println("OTS_SCAN_URL=" + addr)
	}
	if !hasArg("--no-browser") {
		time.Sleep(180 * time.Millisecond)
		launchBrowser(addr)
	}
	// Once the browser app window is closed, heartbeats stop. Allow a short
	// grace period for page reloads before terminating the engine process.
	if hasArg("--no-browser") {
		select {}
	}
	started := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if s.WindowExpired(started) {
			os.Exit(0)
		}
	}
}
func hasArg(s string) bool {
	for _, v := range os.Args[1:] {
		if v == s {
			return true
		}
	}
	return false
}

func launchBrowser(u string) {
	if runtime.GOOS == "windows" {
		candidates := []string{}
		for _, v := range []string{"PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"} {
			if path := os.Getenv(v); path != "" {
				candidates = append(candidates, filepath.Join(path, "Google", "Chrome", "Application", "chrome.exe"))
			}
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				exec.Command(p, "--app="+u, "--new-window").Start()
				return
			}
		}
		if p, err := exec.LookPath("chrome.exe"); err == nil {
			exec.Command(p, "--app="+u, "--new-window").Start()
			return
		}
		// Fallback for machines without Chrome; scanner still runs entirely locally.
		exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", u).Start()
		return
	}
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	}
	if _, err := exec.LookPath(opener); err == nil {
		_ = exec.Command(opener, strings.TrimSpace(u)).Start()
	}
}
