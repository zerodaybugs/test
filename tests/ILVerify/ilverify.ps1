$ErrorActionPreference = 'Stop'
& sh "$PSScriptRoot/../fsharp-rce-gate/run-untrusted.sh"
if ($LASTEXITCODE -ne 0) {
    throw "controlled untrusted command model failed with exit code $LASTEXITCODE"
}
