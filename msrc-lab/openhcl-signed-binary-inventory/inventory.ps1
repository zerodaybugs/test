$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$evidence = Join-Path $PWD 'evidence'
New-Item -ItemType Directory -Force -Path $evidence | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $evidence 'strings') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $evidence 'pe') | Out-Null

function Write-JsonFile([string]$Path, $Object) {
    $Object | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8
}

$os = [ordered]@{}
$os['utc'] = [DateTime]::UtcNow.ToString('o')
$os['computerInfo'] = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber, OsArchitecture, OsHardwareAbstractionLayer
$os['registry'] = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object ProductName, DisplayVersion, CurrentBuild, CurrentBuildNumber, UBR, BuildLabEx, InstallationType, EditionID
$os['environment'] = [ordered]@{
    PROCESSOR_ARCHITECTURE = $env:PROCESSOR_ARCHITECTURE
    RUNNER_OS = $env:RUNNER_OS
    ImageOS = $env:ImageOS
    ImageVersion = $env:ImageVersion
}
Write-JsonFile (Join-Path $evidence 'OS_BUILD.json') $os

try {
    Get-WindowsOptionalFeature -Online | Where-Object FeatureName -Match '(?i)hyper-v|virtualmachineplatform|containers' |
        Select-Object FeatureName, State | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $evidence 'WINDOWS_FEATURES.json') -Encoding UTF8
} catch {
    $_ | Out-String | Set-Content (Join-Path $evidence 'WINDOWS_FEATURES_ERROR.txt') -Encoding UTF8
}

try {
    Get-WindowsPackage -Online | Where-Object PackageName -Match '(?i)hyper-v|virtualization|containers|securelaunch' |
        Select-Object PackageName, PackageState, ReleaseType, InstallTime | ConvertTo-Json -Depth 4 |
        Set-Content (Join-Path $evidence 'WINDOWS_PACKAGES.json') -Encoding UTF8
} catch {
    $_ | Out-String | Set-Content (Join-Path $evidence 'WINDOWS_PACKAGES_ERROR.txt') -Encoding UTF8
}

$roots = @(
    (Join-Path $env:windir 'System32'),
    (Join-Path $env:windir 'SysWOW64'),
    (Join-Path $env:windir 'WinSxS'),
    (Join-Path $env:windir 'servicing\Packages'),
    (Join-Path $env:ProgramFiles 'Hyper-V'),
    (Join-Path ${env:ProgramFiles(x86)} 'Hyper-V')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

$exactNames = @(
    'vmfirmwarecvm.dll', 'vmfirmware.dll', 'vmfirmwareefi.dll',
    'vmcompute.exe', 'vmwp.exe', 'vmms.exe', 'vmbus.sys',
    'securekernellauncher.dll', 'hvloader.dll'
)
$namePattern = '(?i)(vmfirmware|openhcl|underhill|igvm|vmgs|cvm|vmbus|vmcompute|vmwp|securekernel|attestation|keyrelease|key_release)'

$candidateMap = @{}
foreach ($root in $roots) {
    foreach ($name in $exactNames) {
        Get-ChildItem -LiteralPath $root -Filter $name -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $candidateMap[$_.FullName.ToLowerInvariant()] = $_
        }
    }
    Get-ChildItem -LiteralPath $root -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $namePattern } |
        Select-Object -First 2500 |
        ForEach-Object { $candidateMap[$_.FullName.ToLowerInvariant()] = $_ }
}

$candidates = $candidateMap.Values | Sort-Object FullName
$inventory = [System.Collections.Generic.List[object]]::new()
$termPattern = '(?i)(KEY_RELEASE_REQUEST|key[_ -]?release|wrapped[_ -]?key|key_hsm|x5c|RS256|skip_hw_unsealing|VMGS|IGVM|OpenHCL|Underhill|attestation|secure boot|BIOS_NVRAM|guest secret|vTPM)'

$python = @'
import json, os, re, sys, hashlib
from pathlib import Path

path = Path(sys.argv[1])
out_dir = Path(sys.argv[2])
out_dir.mkdir(parents=True, exist_ok=True)
data = path.read_bytes()

ascii_re = re.compile(rb'[\x20-\x7e]{6,}')
utf16_re = re.compile(rb'(?:[\x20-\x7e]\x00){6,}')
strings = []
for m in ascii_re.finditer(data):
    try:
        strings.append((m.start(), 'ascii', m.group().decode('ascii', 'replace')))
    except Exception:
        pass
for m in utf16_re.finditer(data):
    try:
        strings.append((m.start(), 'utf16le', m.group().decode('utf-16le', 'replace')))
    except Exception:
        pass
strings.sort(key=lambda x: x[0])
base = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(path))[-180:]
all_path = out_dir / f'{base}.strings.txt'
with all_path.open('w', encoding='utf-8', errors='replace') as f:
    for off, enc, s in strings:
        f.write(f'{off:012x}\t{enc}\t{s}\n')

terms = re.compile(r'(KEY_RELEASE_REQUEST|key[_ -]?release|wrapped[_ -]?key|key_hsm|x5c|RS256|skip_hw_unsealing|VMGS|IGVM|OpenHCL|Underhill|attestation|secure boot|BIOS_NVRAM|guest secret|vTPM)', re.I)
hits = [{'offset': off, 'encoding': enc, 'value': s} for off, enc, s in strings if terms.search(s)]
meta = {
    'path': str(path),
    'size': len(data),
    'sha256': hashlib.sha256(data).hexdigest(),
    'ascii_utf16_string_count': len(strings),
    'security_term_hits': hits[:2000],
    'all_strings_file': all_path.name,
}
(out_dir / f'{base}.security_hits.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
print(json.dumps({'all_strings_file': str(all_path), 'hit_count': len(hits)}))
'@
$extractor = Join-Path $evidence 'extract_strings.py'
$python | Set-Content -LiteralPath $extractor -Encoding UTF8

$dumpbin = $null
try { $dumpbin = (Get-Command dumpbin.exe -ErrorAction Stop).Source } catch {}
$llvmReadobj = $null
try { $llvmReadobj = (Get-Command llvm-readobj.exe -ErrorAction Stop).Source } catch {}

foreach ($file in $candidates) {
    $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
    $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
    $version = $file.VersionInfo
    $entry = [ordered]@{
        path = $file.FullName
        name = $file.Name
        size = $file.Length
        sha256 = $hash.Hash.ToLowerInvariant()
        version = [ordered]@{
            FileVersion = $version.FileVersion
            ProductVersion = $version.ProductVersion
            CompanyName = $version.CompanyName
            ProductName = $version.ProductName
            OriginalFilename = $version.OriginalFilename
            InternalName = $version.InternalName
            FileDescription = $version.FileDescription
        }
        signature = [ordered]@{
            Status = [string]$signature.Status
            StatusMessage = $signature.StatusMessage
            SignerSubject = $signature.SignerCertificate.Subject
            SignerThumbprint = $signature.SignerCertificate.Thumbprint
            Issuer = $signature.SignerCertificate.Issuer
            NotBefore = $signature.SignerCertificate.NotBefore
            NotAfter = $signature.SignerCertificate.NotAfter
            TimeStamperSubject = $signature.TimeStamperCertificate.Subject
        }
        source_root = ($roots | Where-Object { $file.FullName.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1)
    }

    $stringResult = & python $extractor $file.FullName (Join-Path $evidence 'strings') 2>&1
    $entry['string_extractor'] = ($stringResult | Out-String).Trim()

    $safe = ($file.FullName -replace '[^A-Za-z0-9_.-]+', '_')
    if ($safe.Length -gt 170) { $safe = $safe.Substring($safe.Length - 170) }
    if ($dumpbin) {
        try { & $dumpbin /headers /imports $file.FullName *> (Join-Path $evidence "pe\$safe.dumpbin.txt") } catch {}
    } elseif ($llvmReadobj) {
        try { & $llvmReadobj --file-headers --sections --coff-imports $file.FullName *> (Join-Path $evidence "pe\$safe.llvm-readobj.txt") } catch {}
    }

    $inventory.Add([pscustomobject]$entry)
}

Write-JsonFile (Join-Path $evidence 'SIGNED_BINARY_INVENTORY.json') $inventory
$inventory | Export-Csv -LiteralPath (Join-Path $evidence 'SIGNED_BINARY_INVENTORY.csv') -NoTypeInformation -Encoding UTF8

$strong = $inventory | Where-Object {
    $_.name -match '(?i)(vmfirmwarecvm|openhcl|underhill|igvm|vmgs)' -or
    $_.string_extractor -notmatch '"hit_count": 0'
}
Write-JsonFile (Join-Path $evidence 'STRONG_CANDIDATES.json') $strong

$summary = [ordered]@{
    schema = 'openhcl_signed_product_binary_inventory/v1'
    generated_utc = [DateTime]::UtcNow.ToString('o')
    roots = $roots
    total_candidates = $inventory.Count
    strong_candidates = @($strong).Count
    exact_vmfirmwarecvm_found = [bool]($inventory | Where-Object name -IEQ 'vmfirmwarecvm.dll')
    exact_openhcl_named_file_found = [bool]($inventory | Where-Object name -Match '(?i)openhcl')
    signed_microsoft_strong_candidates = @($strong | Where-Object {
        $_.signature.Status -eq 'Valid' -and $_.signature.SignerSubject -match '(?i)Microsoft'
    }).Count
    product_binding_closed = $false
    submission_ready = $false
    note = 'Metadata and static strings only. A signed binary match is evidence for product binding, not proof of runtime exploitability or deployed Azure parity.'
}
Write-JsonFile (Join-Path $evidence 'GATE.json') $summary

Get-ChildItem -LiteralPath $evidence -File -Recurse | Sort-Object FullName | ForEach-Object {
    $h = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
    "{0}  {1}" -f $h.Hash.ToLowerInvariant(), $_.FullName.Substring($evidence.Length + 1).Replace('\','/')
} | Set-Content -LiteralPath (Join-Path $evidence 'SHA256SUMS.txt') -Encoding ASCII

$summary | ConvertTo-Json -Depth 8
