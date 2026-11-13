# Synthetic, read-only Windows UI Automation check of the *installed* WPF host.
# No real user files are scanned or modified, no quarantine, Defender or cleanup.
param(
    [Parameter(Mandatory = $true)]
    [long] $WindowHandle
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$root = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr]$WindowHandle)
if ($null -eq $root) { throw 'Cannot find installed suite main window via UI Automation' }
if ($root.Current.Name -notlike 'OTS Security Suite*') {
    throw "Unexpected installed suite window title: $($root.Current.Name)"
}
$rect = $root.Current.BoundingRectangle
if ($rect.Width -lt 700 -or $rect.Height -lt 600) {
    throw "Installed suite opened unusably small ($($rect.Width)x$($rect.Height))"
}

function Get-Ui([string] $automationId) {
    $condition = [System.Windows.Automation.PropertyCondition]::new(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty, $automationId)
    $item = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
    if ($null -eq $item) { throw "Missing visible WPF UI control: $automationId" }
    return $item
}

function Click-Ui([string] $automationId) {
    $item = Get-Ui $automationId
    $pattern = $item.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
    $pattern.Invoke()
}

$fixture = Join-Path $env:TEMP ('OTS-Suite-UI-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
try {
    Set-Content -Path (Join-Path $fixture 'hello.py') -Value 'print("harmless CI UI test")' -Encoding utf8
    Click-Ui 'WhiteTab'
    $folder = Get-Ui 'WhiteFolder'
    $folderValue = $folder.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    $folderValue.SetValue($fixture)

    $importControl = Get-Ui 'WhiteImport'
    if (-not $importControl.Current.IsEnabled) { throw 'Import report control was unexpectedly disabled' }
    Click-Ui 'WhiteRun'
    $status = Get-Ui 'WhiteStatus'
    $finished = $false
    for ($i = 0; $i -lt 200; $i++) {
        Start-Sleep -Milliseconds 200
        $label = $status.Current.Name
        if ($label -like 'Audit completed*') {
            $finished = $true
            break
        }
        if ($label -like 'Audit could not finish*' -or $label -like 'Audit incomplete*' -or
            $label -like 'Audit engine failed*' -or $label -like 'Audit timed out*') {
            throw "Installed WPF audit failed synthetic end-to-end check: $label"
        }
    }
    if (-not $finished) { throw "Installed WPF audit did not complete within 40 seconds. Status: $($status.Current.Name)" }
    $output = Get-Ui 'WhiteOutput'
    $outValue = $output.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    $reportText = $outValue.Current.Value
    $report = $reportText | ConvertFrom-Json
    if (-not $report.complete -or $report.scanned_files -ne 1) {
        throw "WPF audit output JSON did not reflect completed single-file synthetic scan"
    }
    $cancel = Get-Ui 'WhiteCancel'
    if ($cancel.Current.IsEnabled) { throw 'Cancel Audit remained enabled after completed run' }
    Write-Host 'PASS WPF UI Automation: navigation, text input, real packaged WHITE execution and JSON presentation'
    # A second native launch must hand off to the first and exit cleanly;
    # running a separate instance would create a second Go scanner.
    $exe = (Get-CimInstance Win32_Process -Filter "ProcessId=$($root.Current.ProcessId)").ExecutablePath
    if (-not $exe) { throw 'Cannot resolve installed suite executable for single-instance smoke' }
    $secondary = Start-Process -FilePath $exe -ArgumentList 'ots-security://scan' -PassThru
    try {
        if (-not $secondary.WaitForExit(15000)) { throw 'Secondary suite instance did not exit' }
        if ($secondary.ExitCode -ne 0) { throw "Secondary protocol activation failed with exit $($secondary.ExitCode)" }
        Write-Host 'PASS WPF UI Automation: second invocation handed off without second window'
    }
    finally {
        $secondary.Refresh()
        if (-not $secondary.HasExited) { Stop-Process -Id $secondary.Id -Force }
        $secondary.Dispose()
    }
    Click-Ui 'SystemTab'
    $system = Get-Ui 'SystemStatus'
    if ($system.Current.Name -notlike '*read-only*') {
        throw 'Windows Security tab did not show initial read-only confirmation'
    }
    Write-Host 'PASS WPF UI Automation: Windows Security tab navigation'
} finally {
    Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
}
