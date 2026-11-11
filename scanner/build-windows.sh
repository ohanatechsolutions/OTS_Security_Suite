#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p release cmd/installer/payload
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0
GOFLAGS='-trimpath' go build -ldflags='-H=windowsgui -s -w' -o release/OTS-GitHub-Malware-Scanner.exe ./cmd/scanner
python3 tools/embed_pe_icon.py release/OTS-GitHub-Malware-Scanner.exe branding/OTS-GitHub-Malware-Scanner.ico
GOFLAGS='-trimpath' go build -ldflags='-H=windowsgui -s -w' -o cmd/installer/payload/OTS-GitHub-Malware-Scanner-Uninstall.exe ./cmd/uninstaller
cp release/OTS-GitHub-Malware-Scanner.exe cmd/installer/payload/OTS-GitHub-Malware-Scanner.exe
cp branding/OTS-GitHub-Malware-Scanner.ico cmd/installer/payload/logo.ico
sha256sum release/OTS-GitHub-Malware-Scanner.exe | cut -d ' ' -f 1 > cmd/installer/payload/checksum.txt
GOFLAGS='-trimpath' go build -ldflags='-H=windowsgui -s -w' -o release/OTS-GitHub-Malware-Scanner-Setup.exe ./cmd/installer
python3 tools/embed_pe_icon.py release/OTS-GitHub-Malware-Scanner-Setup.exe branding/OTS-GitHub-Malware-Scanner.ico
cp cmd/installer/payload/OTS-GitHub-Malware-Scanner-Uninstall.exe release/OTS-GitHub-Malware-Scanner-Uninstall.exe
sha256sum release/*.exe > release/SHA256SUMS.txt
echo 'Windows installer and app created in release/'
