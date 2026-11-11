$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
New-Item -ItemType Directory -Force release,cmd/installer/payload | Out-Null
$env:GOOS="windows"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -trimpath -ldflags="-H=windowsgui -s -w" -o release/OTS-GitHub-Malware-Scanner.exe ./cmd/scanner
if($LASTEXITCODE -ne 0){throw "scanner build failed"}
py -3 tools/embed_pe_icon.py release/OTS-GitHub-Malware-Scanner.exe branding/OTS-GitHub-Malware-Scanner.ico
if($LASTEXITCODE -ne 0){throw "icon embedding failed"}
go build -trimpath -ldflags="-H=windowsgui -s -w" -o cmd/installer/payload/OTS-GitHub-Malware-Scanner-Uninstall.exe ./cmd/uninstaller
if($LASTEXITCODE -ne 0){throw "uninstaller build failed"}
Copy-Item release/OTS-GitHub-Malware-Scanner.exe cmd/installer/payload/OTS-GitHub-Malware-Scanner.exe
Copy-Item branding/OTS-GitHub-Malware-Scanner.ico cmd/installer/payload/logo.ico
(Get-FileHash release/OTS-GitHub-Malware-Scanner.exe -Algorithm SHA256).Hash.ToLowerInvariant() | Set-Content -NoNewline cmd/installer/payload/checksum.txt
go build -trimpath -ldflags="-H=windowsgui -s -w" -o release/OTS-GitHub-Malware-Scanner-Setup.exe ./cmd/installer
if($LASTEXITCODE -ne 0){throw "installer build failed"}
py -3 tools/embed_pe_icon.py release/OTS-GitHub-Malware-Scanner-Setup.exe branding/OTS-GitHub-Malware-Scanner.ico
if($LASTEXITCODE -ne 0){throw "installer icon embedding failed"}
Copy-Item cmd/installer/payload/OTS-GitHub-Malware-Scanner-Uninstall.exe release/OTS-GitHub-Malware-Scanner-Uninstall.exe
Get-FileHash release/*.exe -Algorithm SHA256 | Format-Table -AutoSize
Write-Host "Installer is release/OTS-GitHub-Malware-Scanner-Setup.exe"
