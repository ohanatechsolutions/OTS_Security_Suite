# Local-only release signing. Requires an owner-approved certificate in the
# CurrentUser Windows certificate store and an explicitly approved timestamp URL.
# Execute Bundle stage BEFORE Inno, Installer stage AFTER Inno. Never commit a PFX.
param(
 [Parameter(Mandatory=$true)][ValidateSet('Bundle','Installer')][string]$Stage,
 [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$CertificateThumbprint,
 [Parameter(Mandatory=$true)][ValidatePattern('^https://')][string]$TimestampUrl,
 [string]$BundleDir='.\bundle',
 [string]$InstallerPath='.\artifacts\OTS-Security-Suite-Setup-x64.exe',
 [string]$ExpectedPublisher='Ohana Tech Solutions'
)
$ErrorActionPreference='Stop'
$cert=Get-Item -LiteralPath ("Cert:\CurrentUser\My\"+$CertificateThumbprint) -ErrorAction Stop
if(-not $cert.HasPrivateKey -or $cert.NotAfter -le (Get-Date) -or $cert.NotBefore -gt (Get-Date)){
 throw 'Signing certificate not currently valid or private key unavailable.'
}
if($cert.Subject -notlike "*$ExpectedPublisher*"){throw 'Signing certificate publisher does not match OTS.'}
$tool=(Get-Command signtool.exe -ErrorAction Stop).Source
if($Stage -eq 'Bundle'){
 $root=(Resolve-Path -LiteralPath $BundleDir -ErrorAction Stop).Path
 $targets=@(Get-ChildItem -LiteralPath $root -Filter '*.exe' -Recurse -File |
   Sort-Object FullName | Select-Object -ExpandProperty FullName)
 if($targets.Count -lt 4){throw 'Expected suite, RepoScan, WHITE and Sanitizer executables.'}
} else { $targets=@((Resolve-Path -LiteralPath $InstallerPath -ErrorAction Stop).Path) }
foreach($target in $targets){
 & $tool sign /fd SHA256 /sha1 $CertificateThumbprint /tr $TimestampUrl /td SHA256 $target
 if($LASTEXITCODE -ne 0){throw "Signing failed: $target"}
 & $tool verify /pa /v $target
 if($LASTEXITCODE -ne 0){throw "Signature verification failed: $target"}
 $sig=Get-AuthenticodeSignature -LiteralPath $target
 if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike "*$ExpectedPublisher*"){
  throw "Invalid or wrong publisher signature: $target"
 }
}
if($Stage -eq 'Installer'){
 $out=Join-Path (Split-Path -Parent $targets[0]) 'SHA256SUMS.txt'
 $hash=(Get-FileHash -LiteralPath $targets[0] -Algorithm SHA256).Hash
 "$hash  $(Split-Path -Leaf $targets[0])" | Set-Content -LiteralPath $out -Encoding utf8
 Write-Host "Signed installer checksum recorded in $out"
}
Write-Host "PASS $($targets.Count) verified $Stage signatures"
