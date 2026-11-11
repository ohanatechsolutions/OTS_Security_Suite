//go:build windows
package main
import (
 "fmt"
 "io"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "syscall"
 "unsafe"
)
const regKey=`HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\OTSGitHubMalwareScanner`
func message(title,body string,flags uintptr){
 u:=syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
 a,_:=syscall.UTF16PtrFromString(body);b,_:=syscall.UTF16PtrFromString(title)
 u.Call(0,uintptr(unsafe.Pointer(a)),uintptr(unsafe.Pointer(b)),flags)
}
func main(){
 if len(os.Args)==3 && os.Args[1]=="--remove" {remove(os.Args[2]);return}
 exe,err:=os.Executable();if err!=nil {message("OTS Uninstaller",err.Error(),0x10);return}
 temp,err:=os.CreateTemp("","OTS-Uninstaller-*.exe");if err!=nil {message("OTS Uninstaller",err.Error(),0x10);return}
 in,err:=os.Open(exe);if err!=nil {message("OTS Uninstaller",err.Error(),0x10);return}
 _,err=io.Copy(temp,in);in.Close();temp.Close();if err!=nil {message("OTS Uninstaller",err.Error(),0x10);return}
 dir:=filepath.Dir(exe)
 if err=exec.Command(temp.Name(),"--remove",dir).Start();err!=nil {message("OTS Uninstaller",err.Error(),0x10)}
}
func remove(path string){
 local:=os.Getenv("LOCALAPPDATA");if local==""{message("OTS Uninstaller","LOCALAPPDATA unavailable",0x10);return}
 expected:=filepath.Join(local,"Programs","Ohana Tech Solutions","GitHub Malware Scanner")
 // Never delete arbitrary user-supplied paths.
 a,e:=filepath.Abs(path);b,f:=filepath.Abs(expected)
 if e!=nil||f!=nil||!strings.EqualFold(a,b) {message("OTS Uninstaller","Unexpected installation path. Refusing to remove files.",0x10);return}
 err:=os.RemoveAll(expected)
 _=exec.Command("reg.exe","delete",regKey,"/f").Run()
 ps:=`$w=New-Object -ComObject WScript.Shell;foreach($f in @($w.SpecialFolders.Item('Desktop'),$w.SpecialFolders.Item('Programs'))){$p=Join-Path $f 'GitHub Malware Scanner.lnk';if(Test-Path -LiteralPath $p){Remove-Item -LiteralPath $p -Force}}`
 _=exec.Command("powershell.exe","-NoProfile","-NonInteractive","-Command",ps).Run()
 if err!=nil {message("OTS Uninstaller",fmt.Sprint("Some files could not be removed: ",err),0x30)}else {message("OTS Uninstaller","GitHub Malware Scanner was removed. Your saved scan reports were kept in your profile.",0x40)}
}
