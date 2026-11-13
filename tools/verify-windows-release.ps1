# Read-only PE, checksum, and optional Authenticode validation.
param(
 [Parameter(Mandatory=$true)][string]$InstallerPath,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
 [switch]$RequireTrustedSignature,
 [string]$ExpectedPublisher='Ohana Tech Solutions'
)
$ErrorActionPreference='Stop'
$resolved=(Resolve-Path -LiteralPath $InstallerPath -ErrorAction Stop).Path
$info=Get-Item -LiteralPath $resolved
if($info.Length -lt 4096){throw 'Installer file is incomplete.'}
$stream=[IO.File]::OpenRead($resolved)
try {
 $reader=[IO.BinaryReader]::new($stream)
 if($reader.ReadUInt16() -ne 0x5A4D){throw 'Invalid MZ header.'}
 $stream.Position=0x3c
 $offset=$reader.ReadInt32()
 if($offset -lt 64 -or $offset -gt ($stream.Length-24)){throw 'Invalid PE offset.'}
 $stream.Position=$offset
 if($reader.ReadUInt32() -ne 0x00004550){throw 'Invalid PE signature.'}
} finally { $stream.Dispose() }
$hash=(Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
if(-not $hash.Equals($ExpectedSha256,[StringComparison]::OrdinalIgnoreCase)){
 throw "SHA256 does not match expected $ExpectedSha256 (actual $hash)"
}
$signature=Get-AuthenticodeSignature -LiteralPath $resolved
if($RequireTrustedSignature){
 if($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate){
  throw "Trusted signature required; actual $($signature.Status)"
 }
 if($signature.SignerCertificate.Subject -notlike "*$ExpectedPublisher*"){
  throw 'Unexpected Authenticode publisher identity.'
 }
 if($null -eq $signature.TimeStamperCertificate){throw 'Expected a trusted timestamp.'}
} elseif($signature.Status -ne 'Valid'){
 Write-Warning "PRIVATE TEST BUILD ONLY: $($signature.Status); do not publish as signed."
}
Write-Host "Installer PE and SHA-256 validated: $hash"
Write-Host "Authenticode: $($signature.Status)"
