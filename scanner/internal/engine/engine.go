package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Limits are resource-safety ceilings, NOT extension exclusions.
const (
	MaxFiles                      = 25000
	MaxFileBytes                  = 16 << 20  // full content analysis per file
	MaxTotalBytes           int64 = 384 << 20 // scan-wide bytes processed (including embedded entries)
	MaxFindings                   = 2500
	MaxCoverageEntries            = 50000
	MaxNestedDepth                = 4
	MaxArchiveEntries             = 25000
	MaxArchiveUnpackedBytes int64 = 192 << 20
)

var ErrCoverage = errors.New("resource limits reached")
var longToken = regexp.MustCompile(`[A-Za-z0-9+/]{160,}={0,2}`)
var printable = regexp.MustCompile(`[\x20-\x7E]{8,}`)

type Finding struct {
	RuleID   string `json:"rule_id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Preview  string `json:"preview"`
	Weight   int    `json:"weight"`
}
type Coverage struct {
	Path      string   `json:"path"`
	Type      string   `json:"type"`
	Size      int64    `json:"size"`
	BytesRead int64    `json:"bytes_read"`
	SHA256    string   `json:"sha256,omitempty"`
	HashScope string   `json:"hash_scope,omitempty"`
	Status    string   `json:"status"` // complete | partial | uninspected
	Reason    string   `json:"reason,omitempty"`
	Methods   []string `json:"methods"`
	Embedded  bool     `json:"embedded"`
}
type Report struct {
	ID                  string         `json:"id"`
	Target              string         `json:"target"`
	Type                string         `json:"type"`
	Date                string         `json:"date"`
	Score               int            `json:"score"`
	Verdict             string         `json:"verdict"`
	FilesSeen           int            `json:"files_seen"`    // top-level discovered files only
	FilesScanned        int            `json:"files_scanned"` // top-level with baseline inspection
	FilesSkipped        int            `json:"files_skipped"` // top-level uninspected
	FilesPartial        int            `json:"files_partial"` // top-level partial coverage
	EmbeddedSeen        int            `json:"embedded_seen"`
	EmbeddedScanned     int            `json:"embedded_scanned"`
	EmbeddedPartial     int            `json:"embedded_partial"`
	EmbeddedUninspected int            `json:"embedded_uninspected"`
	BytesScanned        int64          `json:"bytes_scanned"`
	Truncated           bool           `json:"truncated"`
	Warnings            []string       `json:"warnings"`
	Findings            []Finding      `json:"findings"`
	CategoryScores      map[string]int `json:"category_scores"`
	RulesAvailable      int            `json:"rules_available"`
	Engine              string         `json:"engine"`
	Coverage            []Coverage     `json:"coverage"`
}

func NewReport(target, typ string) *Report {
	return &Report{ID: fmt.Sprintf("%d", time.Now().UTC().UnixNano()), Target: target, Type: typ, Date: time.Now().UTC().Format(time.RFC3339), Warnings: []string{}, Findings: []Finding{}, Coverage: []Coverage{}, CategoryScores: map[string]int{}, RulesAvailable: RulesCount(), Engine: "OTS Universal Static Inspection 2.0"}
}
func IsSkippedFolder(s string) bool { return false } // retained API: full inventory includes hidden/dependency folders
func (r *Report) warn(msg string) {
	for _, w := range r.Warnings {
		if w == msg {
			return
		}
	}
	if len(r.Warnings) < 40 {
		r.Warnings = append(r.Warnings, msg)
	}
}
func (r *Report) add(f Finding) {
	if len(r.Findings) >= MaxFindings {
		r.Truncated = true
		r.warn("Finding storage limit reached; report is incomplete.")
		return
	}
	r.Findings = append(r.Findings, f)
}
func (r *Report) record(c Coverage) {
	if !c.Embedded {
		r.FilesSeen++
	} else {
		r.EmbeddedSeen++
	}
	if c.Status == "uninspected" {
		if !c.Embedded {
			r.FilesSkipped++
		} else {
			r.EmbeddedUninspected++
		}
	} else {
		if !c.Embedded {
			r.FilesScanned++
		} else {
			r.EmbeddedScanned++
		}
		if c.Status == "partial" {
			if !c.Embedded {
				r.FilesPartial++
			} else {
				r.EmbeddedPartial++
			}
		}
	}
	if c.Status != "complete" {
		r.Truncated = true
	}
	if len(r.Coverage) < MaxCoverageEntries {
		r.Coverage = append(r.Coverage, c)
	} else {
		r.Truncated = true
		r.warn("Per-file coverage records capped at 50,000 entries.")
	}
}
func (r *Report) Uninspected(path, reason string, embedded bool, size int64) {
	r.record(Coverage{Path: path, Size: size, Type: "unknown", Status: "uninspected", Reason: reason, Methods: []string{"inventory"}, Embedded: embedded})
}
func Shannon(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	n := [256]int{}
	for i := 0; i < len(s); i++ {
		n[s[i]]++
	}
	h := 0.0
	for _, c := range n {
		if c > 0 {
			p := float64(c) / float64(len(s))
			h -= p * math.Log2(p)
		}
	}
	return h
}

// ScanBytes inspects ALL extensions. Input bytes are untrusted data, never executed.
func ScanBytes(report *Report, path string, data []byte) {
	ScanFile(report, path, data, int64(len(data)), false, 0)
}
func ScanFile(report *Report, path string, data []byte, size int64, embedded bool, depth int) {
	if size < 0 {
		report.Uninspected(path, "invalid declared size", embedded, size)
		return
	}
	if report.FilesSeen+report.EmbeddedSeen >= MaxFiles {
		report.Uninspected(path, "repository entry count resource limit", embedded, size)
		return
	}
	if report.BytesScanned >= MaxTotalBytes {
		report.Uninspected(path, "scan-wide byte budget exceeded", embedded, size)
		return
	}
	if len(data) > MaxFileBytes {
		data = data[:MaxFileBytes]
	}
	available := MaxTotalBytes - report.BytesScanned
	if int64(len(data)) > available {
		data = data[:int(available)]
	}
	if size > 0 && len(data) == 0 {
		report.Uninspected(path, "content unavailable within scan budget", embedded, size)
		return
	}
	c := Coverage{Path: path, Size: size, BytesRead: int64(len(data)), Type: detectType(path, data), Status: "complete", Methods: []string{"signature", "sha256", "strings", "heuristics"}, Embedded: embedded}
	if int64(len(data)) < size {
		c.Status = "partial"
		c.Reason = "file exceeds configured analysis budget; prefix inspected"
		report.warn("Some files received partial analysis because of resource limits.")
	}
	sum := sha256.Sum256(data)
	c.SHA256 = hex.EncodeToString(sum[:])
	c.HashScope = "full"
	if c.Status != "complete" {
		c.HashScope = "prefix-only"
	}
	report.BytesScanned += int64(len(data))
	if c.Type == "rar" || c.Type == "7z" || c.Type == "ole" || c.Type == "sqlite" || c.Type == "mp4" || c.Type == "riff" {
		c.Methods = append(c.Methods, "metadata only; no format-specific payload parser")
		report.warn("Some formats received universal inspection only; no deep parser is available (e.g. RAR, 7z, OLE, media).")
	}
	report.record(c)
	inspectBytes(report, path, data, c.Type)
	if depth < MaxNestedDepth && c.Status == "complete" {
		scanContainer(report, path, data, c.Type, depth+1)
	} else if depth >= MaxNestedDepth && isContainer(c.Type) {
		report.Truncated = true
		report.warn("Nested archive depth limit reached.")
	}
}
func inspectBytes(report *Report, path string, data []byte, kind string) {
	if len(data) == 0 {
		return
	}
	if bytes.HasPrefix(data, []byte("version https://git-lfs.github.com/spec/v1")) {
		report.warn("Git LFS pointer found; actual LFS object bytes were not downloaded or scanned.")
		report.add(Finding{"FILE005", "File integrity", "Git LFS pointer, not the original file", "medium", "This is a Git LFS pointer. To examine the actual binary, obtain it through Git LFS and scan the downloaded file.", path, 0, "[LFS pointer]", 6})
	}
	if filepath.Base(path) == ".gitmodules" {
		report.warn("Git submodule configuration found; linked submodule repository contents require separate scanning.")
	}
	if bytes.Contains(data, []byte("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")) {
		report.add(Finding{"TEST001", "Test signatures", "EICAR antivirus test signature", "high", "Harmless EICAR standard test string detected; this does not indicate real malware.", path, 0, "[EICAR test signature]", 18})
	}
	// Detect type mismatches and embedded executable headers without executing data.
	lower := strings.ToLower(path)
	ext := strings.ToLower(filepath.Ext(lower))
	if (ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif") && (kind == "pe" || kind == "elf" || kind == "zip" || kind == "script") {
		report.add(Finding{"FILE001", "File integrity", "Extension disguises other content", "high", "Filename suggests an image, but its content signature indicates another format.", path, 0, "[file signature mismatch]", 16})
	}
	if kind != "pe" && kind != "elf" && kind != "macho" {
		if n := embeddedExecutableOffset(data); n >= 64 {
			report.add(Finding{"FILE002", "Embedded payload", "Possible embedded executable", "medium", "Executable-like header found inside a non-executable file; inspect context for false positives.", path, 0, fmt.Sprintf("[signature offset %d]", n), 10})
		}
	}
	if kind == "pe" || kind == "elf" || kind == "macho" {
		binaryInspection(report, path, data, kind)
	}
	if kind == "pdf" && (bytes.Contains(data, []byte("/JavaScript")) || bytes.Contains(data, []byte("/OpenAction")) || bytes.Contains(data, []byte("/Launch"))) {
		report.add(Finding{"DOC001", "Document threats", "Active PDF actions", "high", "PDF contains active-action indicators; actual exploitability has not been established.", path, 0, "[PDF action tokens]", 14})
	}
	if kind == "ole" {
		report.add(Finding{"DOC002", "Document threats", "Legacy OLE compound file", "low", "Compound documents may contain macros or embedded objects; deep OLE parsing is not implemented.", path, 0, "[OLE container]", 2})
	}
	if kind == "png" {
		if index := bytes.LastIndex(data, []byte("IEND")); index >= 0 && len(data) > index+8 {
			report.add(Finding{"FILE003", "Embedded payload", "Data trailing PNG end marker", "low", "Unexpected trailing content after PNG end marker warrants inspection.", path, 0, "[PNG trailing data]", 5})
		}
	}
	if kind == "jpeg" {
		if i := bytes.LastIndex(data, []byte{0xFF, 0xD9}); i >= 0 && len(data) > i+2 {
			report.add(Finding{"FILE004", "Embedded payload", "Data trailing JPEG marker", "low", "JPEG contains additional data beyond its usual end marker.", path, 0, "[JPEG trailing data]", 5})
		}
	}
	// Apply source-code rules to textual content; also inspect printable strings in binary files.
	if kind == "text" || kind == "script" || kind == "xml" || kind == "json" || kind == "svg" {
		for lineIndex, line := range bytes.Split(data, []byte{'\n'}) {
			if len(line) > 16384 {
				line = line[:16384]
			}
			scanIndicators(report, path, line, lineIndex+1)
		}
	} else {
		scanWideStrings(report, path, data)
		count := 0
		for _, str := range printable.FindAll(data, 3000) {
			if len(str) > 4096 {
				str = str[:4096]
			}
			scanIndicators(report, path, str, 0)
			count++
		}
		_ = count
	}
}
func scanIndicators(report *Report, path string, line []byte, n int) {
	text := string(line)
	for _, rule := range rules {
		if rule.Re.MatchString(text) {
			report.add(Finding{rule.ID, rule.Category, rule.Title, rule.Severity, rule.Detail, path, n, preview(text), rule.Weight})
		}
	}
	for _, m := range longToken.FindAllString(text, 2) {
		if Shannon(m) > 5.1 {
			report.add(Finding{"OBF007", "Obfuscation", "High-entropy encoded string", "medium", "Long high-entropy token may contain an encoded payload (also possible in benign data).", path, n, "[long encoded token omitted]", 9})
		}
	}
}
func preview(s string) string {
	// Do not export code excerpts or possible secrets from untrusted repositories.
	s = strings.TrimSpace(s)
	if len(s) > 0 {
		return "[matched content omitted; inspect original file in a safe editor]"
	}
	return "[no excerpt]"
}
func Finalize(report *Report) {
	score := 0
	unique := map[string]bool{}
	for _, f := range report.Findings {
		k := f.RuleID + "|" + f.File
		if unique[k] {
			continue
		}
		unique[k] = true
		add := f.Weight
		if report.CategoryScores[f.Category] > 25 {
			add = (add + 1) / 2
		}
		score += add
		report.CategoryScores[f.Category] += add
	}
	if score > 100 {
		score = 100
	}
	report.Score = score
	report.Verdict = "LOW INDICATED RISK"
	if score >= 26 {
		report.Verdict = "SUSPICIOUS"
	}
	if score >= 65 {
		report.Verdict = "HIGH INDICATED RISK"
	}
	if report.FilesSkipped > 0 || report.FilesPartial > 0 || report.EmbeddedPartial > 0 || report.EmbeddedUninspected > 0 || report.Truncated {
		report.warn("Coverage incomplete: an absence of findings is NOT a clean bill of health.")
		if score < 26 {
			report.Verdict = "INCOMPLETE ANALYSIS"
		}
	}
	if len(report.Findings) == 0 {
		report.warn("No rules matched. Static analysis cannot establish that software is safe.")
	}
	report.warn("100% inventory coverage does not imply 100% malware detection or complete format parsing.")
	sort.SliceStable(report.Findings, func(i, j int) bool { return report.Findings[i].Weight > report.Findings[j].Weight })
}
func ScanDir(root string) (*Report, error) {
	return ScanDirContext(context.Background(), root)
}

// ScanDirContext stops inventorying and inspecting files when the browser's
// local HTTP request is cancelled. A cancelled scan is never saved as complete.
func ScanDirContext(ctx context.Context, root string) (*Report, error) {
	if err := ctx.Err(); err != nil { return nil, err }
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return nil, errors.New("path is not a regular file or directory")
		}
		report := NewReport(root, "local file")
		f, e := os.Open(root)
		if e != nil {
			return nil, e
		}
		data, e := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
		_ = f.Close()
		if e != nil {
			return nil, e
		}
		if err := ctx.Err(); err != nil { return nil, err }
		ScanFile(report, filepath.Base(root), data, info.Size(), false, 0)
		Finalize(report)
		return report, nil
	}
	report := NewReport(root, "local folder")
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkerr error) error {
		if err := ctx.Err(); err != nil { return err }
		if walkerr != nil {
			report.warn("Folder traversal error: " + walkerr.Error())
			report.Truncated = true
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			report.warn("Cannot make relative path for a directory entry")
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.Type()&os.ModeSymlink != 0 {
			report.Uninspected(rel, "symbolic link is not followed (safety policy)", false, 0)
			return nil
		}
		info, e := d.Info()
		if e != nil {
			report.Uninspected(rel, "cannot stat file", false, 0)
			return nil
		}
		if !info.Mode().IsRegular() {
			report.Uninspected(rel, "special file/device (not read)", false, info.Size())
			return nil
		}
		if report.BytesScanned >= MaxTotalBytes || report.FilesSeen+report.EmbeddedSeen >= MaxFiles {
			report.Uninspected(rel, "scan-wide resource limit reached", false, info.Size())
			return nil
		}
		f, e := os.Open(path)
		if e != nil {
			report.Uninspected(rel, "cannot read file", false, info.Size())
			return nil
		}
		data, e := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
		_ = f.Close()
		if e != nil {
			report.Uninspected(rel, "file read failed", false, info.Size())
			return nil
		}
		if err := ctx.Err(); err != nil { return err }
		ScanFile(report, rel, data, info.Size(), false, 0)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil { return nil, err }
	Finalize(report)
	return report, nil
}
func ReportJSON(r *Report) ([]byte, error) { return json.MarshalIndent(r, "", "  ") }
