//go:build windows

package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

//go:embed payload/OTS-GitHub-Malware-Scanner.exe payload/OTS-GitHub-Malware-Scanner-Uninstall.exe payload/checksum.txt payload/logo.ico
var payload embed.FS

const title = "Ohana Tech Solutions — GitHub Malware Scanner"
const regKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\OTSGitHubMalwareScanner`

func message(body string, flags uintptr) {
	call := syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
	a, _ := syscall.UTF16PtrFromString(body)
	b, _ := syscall.UTF16PtrFromString(title)
	call.Call(0, uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(b)), flags)
}
func reg(name, value string) {
	_ = exec.Command("reg.exe", "add", regKey, "/v", name, "/t", "REG_SZ", "/d", value, "/f").Run()
}
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func main() {
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		message("Windows LOCALAPPDATA path not found", 0x10)
		return
	}
	appDir := filepath.Join(local, "Programs", "Ohana Tech Solutions", "GitHub Malware Scanner")
	scanner, err := payload.ReadFile("payload/OTS-GitHub-Malware-Scanner.exe")
	if err != nil {
		message(err.Error(), 0x10)
		return
	}
	uninstaller, err := payload.ReadFile("payload/OTS-GitHub-Malware-Scanner-Uninstall.exe")
	if err != nil {
		message(err.Error(), 0x10)
		return
	}
	iconData, err := payload.ReadFile("payload/logo.ico")
	if err != nil {
		message(err.Error(), 0x10)
		return
	}
	checksum, err := payload.ReadFile("payload/checksum.txt")
	if err != nil {
		message(err.Error(), 0x10)
		return
	}
	digest := sha256.Sum256(scanner)
	if hex.EncodeToString(digest[:]) != strings.TrimSpace(string(checksum)) {
		message("Installer integrity verification failed. Do not run this package.", 0x10)
		return
	}
	if err = os.MkdirAll(appDir, 0755); err != nil {
		message(err.Error(), 0x10)
		return
	}
	target := filepath.Join(appDir, "OTS-GitHub-Malware-Scanner.exe")
	if err = os.WriteFile(target, scanner, 0755); err != nil {
		message("Installation failed. Close the scanner and retry.\n"+err.Error(), 0x10)
		return
	}
	unTarget := filepath.Join(appDir, "Uninstall.exe")
	if err = os.WriteFile(unTarget, uninstaller, 0755); err != nil {
		message(err.Error(), 0x10)
		return
	}
    iconPath := filepath.Join(appDir, "OTS-Scanner-v2.5.ico")
	if err = os.WriteFile(iconPath, iconData, 0644); err != nil {
		message(err.Error(), 0x10)
		return
	}
	script := fmt.Sprintf(`$w=New-Object -ComObject WScript.Shell;$target=%s;foreach($f in @($w.SpecialFolders.Item('Desktop'),$w.SpecialFolders.Item('Programs'))){$p=Join-Path $f 'GitHub Malware Scanner.lnk';$s=$w.CreateShortcut($p);$s.TargetPath=$target;$s.WorkingDirectory=Split-Path $target;$s.Description='OTS GitHub Malware Scanner - Independent Local Scanner';$s.IconLocation=%s;$s.Save()}`, psQuote(target), psQuote(iconPath))
	if err = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Run(); err != nil {
		message("Scanner installed, but shortcuts could not be created.\n"+err.Error(), 0x30)
	}
	reg("DisplayName", "GitHub Malware Scanner (Ohana Tech Solutions)")
	reg("Publisher", "Ohana Tech Solutions")
	reg("DisplayVersion", "2.5.0")
	reg("InstallLocation", appDir)
	reg("UninstallString", `"`+unTarget+`"`)
	reg("NoModify", "1")
	message("GitHub Malware Scanner has been installed for your Windows account.\n\nIt runs a local scanning engine; it is NOT ScanRepo's original application.\n\nClick OK to launch.", 0x40)
	_ = exec.Command(target).Start()
}
