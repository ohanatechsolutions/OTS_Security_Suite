# Generate a nonsecret, source-to-build provenance record for the installed suite.
# This is a direct-component inventory, NOT a full transitive CycloneDX/SPDX SBOM.
param([Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $repo
try {
    $project=[xml](Get-Content -LiteralPath 'src/OTSSecuritySuite.Desktop/OTSSecuritySuite.Desktop.csproj' -Raw)
    $suiteVersion=[string]$project.Project.PropertyGroup.Version
    $webview= @($project.Project.ItemGroup.PackageReference |
        Where-Object { $_.Include -eq 'Microsoft.Web.WebView2' } |
        Select-Object -First 1)
    if($webview.Count -ne 1){throw 'Expected one pinned WebView2 NuGet reference.'}
    $webviewVersion=[string]$webview[0].Version

    $checkout=([string](& git rev-parse HEAD)).Trim()
    $white=([string](& git -C modules/OTS_WHITE rev-parse HEAD)).Trim()
    $sanitizer=([string](& git -C modules/OTS_System_Sanitizer rev-parse HEAD)).Trim()
    foreach($sha in @($checkout,$white,$sanitizer)){
        if($sha -notmatch '^[a-fA-F0-9]{40}$'){throw 'Invalid source or submodule commit.'}
    }
    $go=([string](& go version)).Trim()
    $net=([string](& dotnet --version)).Trim()
    $python=([string](& python --version)).Trim()
    $pip= @(& python -m pip show pyinstaller)
    $installerVersion= (($pip | Where-Object { $_ -match '^Version:\s+' } | Select-Object -First 1) -replace '^Version:\s+','').Trim()
    if(-not $installerVersion){throw 'PyInstaller packaging version not discoverable.'}
    $innoCompiler=Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
    if(-not [IO.File]::Exists($innoCompiler)){throw 'Inno Setup 6 compiler is unavailable.'}
    $innoInfo=Get-Item -LiteralPath $innoCompiler -ErrorAction Stop
    $innoVersion=@($innoInfo.VersionInfo.FileVersion,$innoInfo.VersionInfo.ProductVersion) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -First 1
    if(-not $innoVersion){$innoVersion='not-present-in-PE-version-resource'}
    $innoSha256=(Get-FileHash -LiteralPath $innoCompiler -Algorithm SHA256).Hash
    if($innoSha256 -notmatch '^[A-Fa-f0-9]{64}$'){throw 'Inno compiler binary checksum invalid.'}

    $components=@(
        [ordered]@{ name='OTSSecuritySuite.Desktop'; type='WPF app'; version=$suiteVersion;
            framework='net10.0-windows'; source='src/OTSSecuritySuite.Desktop' },
        [ordered]@{ name='Microsoft.Web.WebView2'; type='NuGet SDK/runtime integration';
            version=$webviewVersion; source='Microsoft NuGet package' },
        [ordered]@{ name='RepoScan'; type='Go local/static scanner'; version='2.5.0';
            source='scanner/'; external_go_dependencies='none in go.mod' },
        [ordered]@{ name='OTS W.H.I.T.E.'; type='Python CLI submodule'; commit=$white;
            source='modules/OTS_WHITE' },
        [ordered]@{ name='OTS System Sanitizer'; type='.NET submodule'; commit=$sanitizer;
            source='modules/OTS_System_Sanitizer' },
        [ordered]@{ name='PyInstaller'; type='build-only packaging'; version=$installerVersion },
        [ordered]@{ name='Inno Setup'; type='build-only Windows compiler'; version=$innoVersion; binary_sha256=$innoSha256 }
    )

    $manifest=[ordered]@{
        schema='ots.security-suite.build-manifest.v1'
        build_generated_utc=[DateTime]::UtcNow.ToString('o')
        source=[ordered]@{
            repo='ohanatechsolutions/OTS_Security_Suite'
            checked_out_commit=$checkout
            white_submodule_commit=$white
            sanitizer_submodule_commit=$sanitizer
        }
        product=[ordered]@{name='OTS Security Suite'; version=$suiteVersion;
            target='win-x64'; stage='unsigned integration preview'}
        toolchains=[ordered]@{go=$go; dotnet_sdk=$net; python=$python;
            pyinstaller=$installerVersion; inno_setup=$innoVersion; inno_setup_sha256=$innoSha256}
        direct_components=$components
        evidence_scope='Direct components and build tools only; NOT a full transitive SBOM or vulnerability certification.'
        separate_dependencies=@('Microsoft Edge WebView2 Runtime on target Windows machine',
            'Offline OSV-Scanner and pre-populated cache only if user selects SCA')
        privacy='No credentials, username, source code or raw scan results recorded.'
    }
    $full=[IO.Path]::GetFullPath($OutputPath)
    $directory=[IO.Path]::GetDirectoryName($full)
    if(-not [IO.Directory]::Exists($directory)){throw "Manifest directory does not exist: $directory"}
    $temporary=[IO.Path]::Combine($directory,'.ots-build-manifest-'+[Guid]::NewGuid().ToString('N')+'.tmp')
    try {
        $json=ConvertTo-Json -InputObject $manifest -Depth 10
        [IO.File]::WriteAllText($temporary,$json,[Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporary,$full,$true)
    } finally {
        if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}
    }
    Write-Host "OTS direct-component build manifest prepared (no secrets): $full"
}
finally { Pop-Location }
