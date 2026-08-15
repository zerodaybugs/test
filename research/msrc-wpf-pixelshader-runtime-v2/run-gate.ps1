param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Evidence = Join-Path $ScriptRoot 'evidence'
$RunDir = Join-Path $Evidence 'runs'
$DumpDir = Join-Path $Evidence 'dumps'
$EnvironmentDir = Join-Path $Evidence 'environment'
$SourceDir = Join-Path $Evidence 'source'
$PublishDir = Join-Path $ScriptRoot 'publish'
$RuntimeDir = Join-Path $env:RUNNER_TEMP 'dotnet-windowsdesktop-10.0.11'
$StartTime = Get-Date

Remove-Item $Evidence -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $PublishDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $Evidence, $RunDir, $DumpDir, $EnvironmentDir, $SourceDir | Out-Null

function Write-JsonFile {
    param(
        [Parameter(Mandatory)] [object] $Value,
        [Parameter(Mandatory)] [string] $Path,
        [int] $Depth = 12
    )
    $Value | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding utf8
}

function Get-Sha256Lower {
    param([Parameter(Mandatory)] [string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Convert-ExitCodeToHex {
    param([int] $ExitCode)
    $bytes = [BitConverter]::GetBytes($ExitCode)
    $unsigned = [BitConverter]::ToUInt32($bytes, 0)
    return ('0x{0:X8}' -f $unsigned)
}

# Environment provenance.
@(
    "start_utc=$($StartTime.ToUniversalTime().ToString('O'))"
    "runner_os=$env:RUNNER_OS"
    "runner_arch=$env:RUNNER_ARCH"
    "computer_name=$env:COMPUTERNAME"
    "powershell=$($PSVersionTable.PSVersion)"
) | Set-Content -LiteralPath (Join-Path $EnvironmentDir 'runner.txt') -Encoding utf8

dotnet --info | Set-Content -LiteralPath (Join-Path $EnvironmentDir 'build-sdk-dotnet-info.txt') -Encoding utf8
dotnet --list-sdks | Set-Content -LiteralPath (Join-Path $EnvironmentDir 'build-sdk-list.txt') -Encoding utf8
dotnet --list-runtimes | Set-Content -LiteralPath (Join-Path $EnvironmentDir 'build-runtime-list.txt') -Encoding utf8

# Install the exact released Windows Desktop runtime under an isolated DOTNET_ROOT.
$InstallScript = Join-Path $env:RUNNER_TEMP 'dotnet-install.ps1'
Invoke-WebRequest -UseBasicParsing 'https://dot.net/v1/dotnet-install.ps1' -OutFile $InstallScript
& $InstallScript -Runtime windowsdesktop -Version '10.0.11' -Architecture x64 -InstallDir $RuntimeDir -NoPath |
    Tee-Object -FilePath (Join-Path $EnvironmentDir 'runtime-install.log')
if ($LASTEXITCODE -ne 0) {
    throw "dotnet-install Windows Desktop runtime failed with exit code $LASTEXITCODE"
}

$RuntimeDotnet = Join-Path $RuntimeDir 'dotnet.exe'
if (-not (Test-Path -LiteralPath $RuntimeDotnet)) {
    throw "Exact runtime dotnet host missing: $RuntimeDotnet"
}

& $RuntimeDotnet --info | Set-Content -LiteralPath (Join-Path $EnvironmentDir 'exact-runtime-dotnet-info.txt') -Encoding utf8
& $RuntimeDotnet --list-runtimes | Set-Content -LiteralPath (Join-Path $EnvironmentDir 'exact-runtime-list.txt') -Encoding utf8
$ExactRuntimeLine = (& $RuntimeDotnet --list-runtimes | Where-Object { $_ -match '^Microsoft\.WindowsDesktop\.App 10\.0\.11 ' })
if (-not $ExactRuntimeLine) {
    throw 'Exact Microsoft.WindowsDesktop.App 10.0.11 was not installed.'
}
$ExactRuntimeLine | Set-Content -LiteralPath (Join-Path $EnvironmentDir 'exact-runtime-selected.txt') -Encoding utf8

$DesktopShared = Join-Path $RuntimeDir 'shared\Microsoft.WindowsDesktop.App\10.0.11'
if (-not (Test-Path -LiteralPath $DesktopShared)) {
    throw "Exact Windows Desktop shared framework directory missing: $DesktopShared"
}

$RuntimeFiles = @()
foreach ($Name in @('wpfgfx_cor3.dll', 'PresentationCore.dll', 'PresentationFramework.dll', 'WindowsBase.dll', 'DirectWriteForwarder.dll')) {
    $Path = Join-Path $DesktopShared $Name
    if (Test-Path -LiteralPath $Path) {
        $Item = Get-Item -LiteralPath $Path
        $RuntimeFiles += [ordered]@{
            name = $Name
            path = $Path
            bytes = $Item.Length
            sha256 = Get-Sha256Lower $Path
            file_version = $Item.VersionInfo.FileVersion
            product_version = $Item.VersionInfo.ProductVersion
        }
    }
}
Write-JsonFile $RuntimeFiles (Join-Path $EnvironmentDir 'exact-runtime-files.json')

# Source provenance: exact released WPF tag and load-bearing parser source.
$WpfClone = Join-Path $env:RUNNER_TEMP 'dotnet-wpf-v10.0.11'
Remove-Item $WpfClone -Recurse -Force -ErrorAction SilentlyContinue
git clone --depth 1 --branch v10.0.11 https://github.com/dotnet/wpf.git $WpfClone 2>&1 |
    Tee-Object -FilePath (Join-Path $SourceDir 'git-clone.log')
if ($LASTEXITCODE -ne 0) {
    throw "dotnet/wpf clone failed with exit code $LASTEXITCODE"
}
$WpfCommit = (git -C $WpfClone rev-parse HEAD).Trim()
$WpfStatus = git -C $WpfClone status --porcelain=v1
$WpfCommit | Set-Content -LiteralPath (Join-Path $SourceDir 'WPF_COMMIT.txt') -Encoding ascii
$WpfStatus | Set-Content -LiteralPath (Join-Path $SourceDir 'WPF_STATUS.txt') -Encoding utf8
if ($WpfStatus) {
    throw 'Exact WPF source checkout was not clean.'
}
$ParserSource = Join-Path $WpfClone 'src\Microsoft.DotNet.Wpf\src\WpfGfx\core\fxjit\PixelShader\pstrans.cpp'
if (-not (Test-Path -LiteralPath $ParserSource)) {
    throw "PixelShader parser source missing: $ParserSource"
}
Copy-Item -LiteralPath $ParserSource -Destination (Join-Path $SourceDir 'pstrans.cpp')
@(
    "tag=v10.0.11"
    "commit=$WpfCommit"
    "pstrans_sha256=$(Get-Sha256Lower $ParserSource)"
) | Set-Content -LiteralPath (Join-Path $SourceDir 'SOURCE_PROVENANCE.txt') -Encoding utf8

# Build the x64 framework-dependent apphost.
dotnet publish (Join-Path $ScriptRoot 'WpfShaderGate.csproj') `
    -c Release `
    -r win-x64 `
    --self-contained false `
    -p:UseAppHost=true `
    -o $PublishDir 2>&1 |
    Tee-Object -FilePath (Join-Path $Evidence 'build.log')
if ($LASTEXITCODE -ne 0) {
    throw "Harness publish failed with exit code $LASTEXITCODE"
}

$Exe = Join-Path $PublishDir 'WpfShaderGate.exe'
if (-not (Test-Path -LiteralPath $Exe)) {
    throw "Harness apphost missing: $Exe"
}

$PublishFiles = foreach ($File in Get-ChildItem -LiteralPath $PublishDir -File | Sort-Object Name) {
    [ordered]@{
        name = $File.Name
        bytes = $File.Length
        sha256 = Get-Sha256Lower $File.FullName
        file_version = $File.VersionInfo.FileVersion
    }
}
Write-JsonFile $PublishFiles (Join-Path $EnvironmentDir 'publish-files.json')

# Force this apphost to resolve only the isolated released runtime.
$env:DOTNET_ROOT = $RuntimeDir
$env:DOTNET_MULTILEVEL_LOOKUP = '0'
$env:COMPlus_legacyCorruptedStateExceptionsPolicy = '1'
$env:COMPlus_HeapVerify = '1'

# Configure full user-mode dumps for the harness only.
$WerKey = 'HKCU:\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\WpfShaderGate.exe'
New-Item -Path $WerKey -Force | Out-Null
New-ItemProperty -Path $WerKey -Name DumpFolder -PropertyType ExpandString -Value $DumpDir -Force | Out-Null
New-ItemProperty -Path $WerKey -Name DumpType -PropertyType DWord -Value 2 -Force | Out-Null
New-ItemProperty -Path $WerKey -Name DumpCount -PropertyType DWord -Value 100 -Force | Out-Null

# Enable full page heap when the Windows debugger tools are available.
$GflagsCandidates = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\gflags.exe",
    "$env:ProgramFiles\Windows Kits\10\Debuggers\x64\gflags.exe"
)
$Gflags = $GflagsCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$PageHeapEnabled = $false
if ($Gflags) {
    & $Gflags /p /enable WpfShaderGate.exe /full 2>&1 |
        Tee-Object -FilePath (Join-Path $EnvironmentDir 'gflags-enable.log')
    $PageHeapEnabled = ($LASTEXITCODE -eq 0)
    & $Gflags /p 2>&1 | Set-Content -LiteralPath (Join-Path $EnvironmentDir 'gflags-status.txt') -Encoding utf8
}
else {
    'gflags.exe not present on the runner' | Set-Content -LiteralPath (Join-Path $EnvironmentDir 'gflags-status.txt') -Encoding utf8
}

$Cases = @(
    [ordered]@{ name = 'end_only'; iterations = 3; timeout_seconds = 45 },
    [ordered]@{ name = 'dcl_length_0'; iterations = 5; timeout_seconds = 45 },
    [ordered]@{ name = 'dcl_length_1'; iterations = 5; timeout_seconds = 45 },
    [ordered]@{ name = 'dcl_length_2'; iterations = 5; timeout_seconds = 45 },
    [ordered]@{ name = 'dcl_length_15'; iterations = 5; timeout_seconds = 45 },
    [ordered]@{ name = 'dcl_desync_1'; iterations = 5; timeout_seconds = 45 },
    [ordered]@{ name = 'dcl_desync_64'; iterations = 5; timeout_seconds = 60 },
    [ordered]@{ name = 'dcl_desync_1024'; iterations = 3; timeout_seconds = 75 },
    [ordered]@{ name = 'dcl_desync_8192'; iterations = 2; timeout_seconds = 90 },
    [ordered]@{ name = 'dcl_desync_65536'; iterations = 1; timeout_seconds = 120 },
    [ordered]@{ name = 'sampler_s15'; iterations = 10; timeout_seconds = 60 },
    [ordered]@{ name = 'sampler_s16'; iterations = 10; timeout_seconds = 60 },
    [ordered]@{ name = 'sampler_s31'; iterations = 10; timeout_seconds = 60 },
    [ordered]@{ name = 'sampler_s255'; iterations = 10; timeout_seconds = 60 },
    [ordered]@{ name = 'sampler_s2047'; iterations = 10; timeout_seconds = 60 },
    [ordered]@{ name = 'sampler_s16_decltype0'; iterations = 10; timeout_seconds = 60 },
    [ordered]@{ name = 'sampler_s31_decltype0'; iterations = 10; timeout_seconds = 60 },
    [ordered]@{ name = 'sampler_s16_repeat_64'; iterations = 5; timeout_seconds = 75 },
    [ordered]@{ name = 'sampler_s31_repeat_64'; iterations = 5; timeout_seconds = 75 },
    [ordered]@{ name = 'sampler_s2047_repeat_64'; iterations = 5; timeout_seconds = 75 },
    [ordered]@{ name = 'sampler_s2047_repeat_512'; iterations = 2; timeout_seconds = 120 }
)

$Rows = @()
try {
    foreach ($Case in $Cases) {
        $CaseName = [string]$Case.name
        $Iterations = [int]$Case.iterations
        $TimeoutSeconds = [int]$Case.timeout_seconds
        $CaseBase = Join-Path $RunDir $CaseName
        $Stdout = "$CaseBase.stdout.txt"
        $Stderr = "$CaseBase.stderr.txt"
        $AppResult = "$CaseBase.app.json"
        $ProcessResult = "$CaseBase.process.json"
        $BeforeDumps = @(Get-ChildItem -LiteralPath $DumpDir -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
        $CaseStart = Get-Date
        $TimedOut = $false
        $StartError = $null
        $ExitCode = $null

        try {
            $Process = Start-Process -FilePath $Exe `
                -ArgumentList @($CaseName, $Iterations, $AppResult) `
                -WorkingDirectory $PublishDir `
                -RedirectStandardOutput $Stdout `
                -RedirectStandardError $Stderr `
                -PassThru

            if (-not $Process.WaitForExit($TimeoutSeconds * 1000)) {
                $TimedOut = $true
                try { $Process.Kill($true) } catch { }
                try { $Process.WaitForExit(10000) | Out-Null } catch { }
            }
            if ($Process.HasExited) {
                $ExitCode = [int]$Process.ExitCode
            }
        }
        catch {
            $StartError = $_.Exception.ToString()
        }

        Start-Sleep -Seconds 4
        $AfterDumps = @(Get-ChildItem -LiteralPath $DumpDir -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
        $NewDumps = @($AfterDumps | Where-Object { $_ -notin $BeforeDumps })
        $CaseEnd = Get-Date
        $ExitHex = if ($null -ne $ExitCode) { Convert-ExitCodeToHex $ExitCode } else { $null }

        $Row = [ordered]@{
            case = $CaseName
            iterations = $Iterations
            timeout_seconds = $TimeoutSeconds
            start_utc = $CaseStart.ToUniversalTime().ToString('O')
            end_utc = $CaseEnd.ToUniversalTime().ToString('O')
            duration_ms = [int64]($CaseEnd - $CaseStart).TotalMilliseconds
            timed_out = $TimedOut
            exit_code_signed = $ExitCode
            exit_code_hex = $ExitHex
            start_error = $StartError
            app_result_exists = Test-Path -LiteralPath $AppResult
            stdout_bytes = if (Test-Path -LiteralPath $Stdout) { (Get-Item -LiteralPath $Stdout).Length } else { 0 }
            stderr_bytes = if (Test-Path -LiteralPath $Stderr) { (Get-Item -LiteralPath $Stderr).Length } else { 0 }
            new_dump_count = $NewDumps.Count
            new_dumps = @($NewDumps | ForEach-Object { Split-Path -Leaf $_ })
        }
        Write-JsonFile $Row $ProcessResult
        $Rows += $Row
    }
}
finally {
    Remove-Item -Path $WerKey -Recurse -Force -ErrorAction SilentlyContinue
    if ($Gflags -and $PageHeapEnabled) {
        & $Gflags /p /disable WpfShaderGate.exe 2>&1 |
            Set-Content -LiteralPath (Join-Path $EnvironmentDir 'gflags-disable.log') -Encoding utf8
    }
}

# Capture relevant application-error events after all isolated cases finish.
try {
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $StartTime } -ErrorAction Stop |
        Where-Object {
            $_.ProviderName -in @('Application Error', 'Windows Error Reporting', '.NET Runtime') -or
            $_.Message -match 'WpfShaderGate|wpfgfx|PresentationCore'
        } |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath (Join-Path $Evidence 'application-events.json') -Encoding utf8
}
catch {
    $_.Exception.ToString() | Set-Content -LiteralPath (Join-Path $Evidence 'application-events-error.txt') -Encoding utf8
}

$NativeCrashCodes = @(
    '0xC0000005', # access violation
    '0xC000001D', # illegal instruction
    '0xC0000094', # integer divide by zero
    '0xC00000FD', # stack overflow
    '0xC0000374', # heap corruption
    '0xC0000409', # stack buffer overrun / fail fast
    '0x80000003'  # breakpoint, often page heap
)
$ControlledExitCodes = @(0, 42, 43, 44)
$DumpFiles = @(Get-ChildItem -LiteralPath $DumpDir -File -ErrorAction SilentlyContinue)
$CrashRows = @($Rows | Where-Object { $_.exit_code_hex -in $NativeCrashCodes -or $_.new_dump_count -gt 0 })
$TimeoutRows = @($Rows | Where-Object { $_.timed_out })
$UnexpectedRows = @($Rows | Where-Object {
    $null -eq $_.exit_code_signed -or
    ($_.exit_code_signed -notin $ControlledExitCodes -and $_.exit_code_hex -notin $NativeCrashCodes)
})

$Classification = if ($CrashRows.Count -gt 0 -or $DumpFiles.Count -gt 0) {
    'NATIVE_CRASH_CAPTURED'
}
elseif ($TimeoutRows.Count -gt 0) {
    'HOLD_TIMEOUT_OR_HANG_ONLY'
}
elseif ($UnexpectedRows.Count -gt 0) {
    'HOLD_UNEXPECTED_PROCESS_TERMINATION_NO_DUMP'
}
else {
    'HOLD_NO_NATIVE_MEMORY_SAFETY_SIGNAL'
}

$MachineResult = [ordered]@{
    schema = 2
    generated_utc = (Get-Date).ToUniversalTime().ToString('O')
    classification = $Classification
    submission_ready = $false
    critical_defensible = $false
    exact_runtime = 'Microsoft.WindowsDesktop.App 10.0.11 x64'
    exact_wpf_tag = 'v10.0.11'
    exact_wpf_commit = $WpfCommit
    page_heap_enabled = $PageHeapEnabled
    local_synthetic_only = $true
    row_count = $Rows.Count
    crash_row_count = $CrashRows.Count
    timeout_row_count = $TimeoutRows.Count
    unexpected_row_count = $UnexpectedRows.Count
    dump_count = $DumpFiles.Count
    crash_rows = $CrashRows
    timeout_rows = $TimeoutRows
    unexpected_rows = $UnexpectedRows
    rows = $Rows
    next_gate = if ($Classification -eq 'NATIVE_CRASH_CAPTURED') {
        'Reproduce 10/10, inspect dump faulting instruction, build exact unmodified and patched WPF native assemblies, prove fix-kill and application input boundary.'
    } else {
        'Do not submit. Retire these payloads or derive a source-accurate predicate/index payload before another Windows run.'
    }
}
Write-JsonFile $MachineResult (Join-Path $Evidence 'MACHINE_RESULT.json') 20

$VerdictText = @(
    '# WPF PixelShader Windows runtime gate'
    ''
    "Formal classification: `$Classification`"
    ''
    'Submission-ready: `NO`'
    'Critical defensible: `NO`'
    'Exact runtime: `Microsoft.WindowsDesktop.App 10.0.11 x64`'
    "Exact WPF source commit: `$WpfCommit`"
    "Full page heap enabled: `$PageHeapEnabled`"
    "Crash rows: `$($CrashRows.Count)`"
    "Dump files: `$($DumpFiles.Count)`"
    "Timeout rows: `$($TimeoutRows.Count)`"
    ''
    'This is an isolated researcher-controlled Windows runtime gate. No external system was tested.'
)
$VerdictText | Set-Content -LiteralPath (Join-Path $Evidence 'VERDICT.md') -Encoding utf8

# Hash every evidence file. Dump files are included by hash, not parsed or modified.
$Manifest = @()
foreach ($File in Get-ChildItem -LiteralPath $Evidence -Recurse -File | Sort-Object FullName) {
    if ($File.Name -eq 'SHA256SUMS.txt') { continue }
    $Relative = $File.FullName.Substring($Evidence.Length).TrimStart('\') -replace '\\', '/'
    $Manifest += "$(Get-Sha256Lower $File.FullName)  $Relative"
}
$Manifest | Set-Content -LiteralPath (Join-Path $Evidence 'SHA256SUMS.txt') -Encoding ascii

Get-Content -LiteralPath (Join-Path $Evidence 'MACHINE_RESULT.json')
