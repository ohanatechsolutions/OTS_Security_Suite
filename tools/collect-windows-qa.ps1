# Non-destructive local Windows evidence collector. No elevation, scans, deletion,
# network calls, credentials or automatic upload.
param([string]$OutputPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){
 throw 'This QA preflight must run on Windows.'
}
$root=Join-Path $env:LOCALAPPDATA 'Programs\Ohana Tech Solutions\Security Suite'
$main=Join-Path $root 'OTSSecuritySuite.exe'
$installed=Test-Path -LiteralPath $main -PathType Leaf
$keyPath='HKCU:\Software\Classes\ots-security\shell\open\command'
$registered=Test-Path -LiteralPath $keyPath
$rightHandler=$false
if($registered){
 try {
  $key=Get-Item -LiteralPath $keyPath -ErrorAction Stop
  $rightHandler=$key.GetValue('') -like '*OTSSecuritySuite.exe*'
 } catch { $rightHandler=$false }
}
$signature='NotInstalled';$hash=$null;$version=$null
if($installed){
 $signature=(Get-AuthenticodeSignature -LiteralPath $main).Status.ToString()
 $hash=(Get-FileHash -LiteralPath $main -Algorithm SHA256).Hash
 $version=(Get-Item -LiteralPath $main).VersionInfo.ProductVersion
}
$webViewDetected=$false
$baseDirs=@()
$pf86=[Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
if($pf86){$baseDirs+=(Join-Path $pf86 'Microsoft\EdgeWebView\Application')}
if($env:LOCALAPPDATA){$baseDirs+=(Join-Path $env:LOCALAPPDATA 'Microsoft\EdgeWebView\Application')}
foreach($dir in $baseDirs){
 if(-not (Test-Path -LiteralPath $dir -PathType Container)){continue}
 foreach($v in (Get-ChildItem -LiteralPath $dir -Directory -ErrorAction SilentlyContinue)){
  if(Test-Path -LiteralPath (Join-Path $v.FullName 'msedgewebview2.exe')){$webViewDetected=$true;break}
 }
 if($webViewDetected){break}
}
$dpi=$null
try{
 if(-not ('OTS_QA_DPI' -as [type])){
  Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class OTS_QA_DPI {
  [DllImport("user32.dll")] public static extern uint GetDpiForSystem();
}
'@
 }
 $dpi=[int][OTS_QA_DPI]::GetDpiForSystem()
}catch{$dpi=$null}
$os=Get-CimInstance Win32_OperatingSystem
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
$report=[ordered]@{
 schema='ots.security-suite.windows.preflight.v1'
 collected_utc=[DateTime]::UtcNow.ToString('o')
 state='AUTOMATED_PREFLIGHT_ONLY_MANUAL_QA_REQUIRED'
 windows=[ordered]@{
  caption=$os.Caption;version=$os.Version;build=$os.BuildNumber
  architecture=$os.OSArchitecture;system_dpi=$dpi
  scale_percent=if($null -ne $dpi){[int][Math]::Round($dpi/96.0*100)}else{$null}
  running_as_admin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 }
 application=[ordered]@{
  installed=$installed;product_version=$version;sha256=$hash
  authenticode=$signature;native_protocol_registered=$registered
  native_protocol_targets_suite=$rightHandler
 }
 webview2=[ordered]@{runtime_path_detected=$webViewDetected;diagnostic_only=$true}
 manual_acceptance=[ordered]@{
  dpi_taskbar_logo='NOT_RUN';chrome_clean_profile='NOT_RUN'
  defender_permission_and_vault_recovery='NOT_RUN'
  win10_win11_real_device='NOT_RUN';owner_signoff='NOT_RUN'
 }
}
$json=ConvertTo-Json -InputObject $report -Depth 8
if($OutputPath){
 $full=[IO.Path]::GetFullPath($OutputPath)
 $dir=[IO.Path]::GetDirectoryName($full)
 if(-not [IO.Directory]::Exists($dir)){throw "QA report folder missing: $dir"}
 $stream=[IO.FileStream]::new($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{
  $writer=[IO.StreamWriter]::new($stream,[Text.UTF8Encoding]::new($false))
  try{$writer.Write($json);$writer.Flush()}finally{$writer.Dispose()}
 }finally{$stream.Dispose()}
 Write-Host "Local QA evidence saved: $full"
}
Write-Host "Windows build $($os.BuildNumber); Suite installed $installed; native URL handler $rightHandler"
Write-Host "WebView2 installation path detected $webViewDetected; DPI $dpi; Authenticode $signature"
Write-Host 'This is non-destructive automated preflight, NOT a substitute for manual QA.'
