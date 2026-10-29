# Push main to GitHub and rebuild on the box.
#
#   scripts/deploy.ps1                         # rebuild everything that changed
#   scripts/deploy.ps1 -Services server
#
# The repo is public, so the checkout on the box pulls straight from GitHub over
# https: push origin, then reset the box's checkout to origin/main and rebuild.
# .env on the box is untracked and survives the reset.
param(
    [string[]]$Services = @(),
    [string]$RemoteHost = 'cctv',
    [string]$RemoteDir = '/home/ziggy/stream-thing-sync'
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Push-Location $repo

function Invoke-Step {
    param([string]$What, [scriptblock]$Command)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $global:LASTEXITCODE = 0
        & $Command 2>&1 | ForEach-Object { Write-Host $_ }
    } finally { $ErrorActionPreference = $previous }
    if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" }
}

try {
    if ((git status --porcelain) -ne $null) {
        throw "Working tree is dirty - commit before deploying so the server matches a real commit."
    }
    $sha = (git rev-parse --short HEAD).Trim()
    Write-Output "deploying $sha to $RemoteHost"
    Invoke-Step "push to origin" { git push origin main }
    # `-Services a,b` from -File arrives as one string; split it.
    $svc = ($Services -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ' '
    Invoke-Step "update and rebuild on $RemoteHost" {
        ssh $RemoteHost "set -e; cd $RemoteDir; git fetch -q origin; git reset --hard -q origin/main; docker compose up -d --build $svc"
    }
    Invoke-Step "status" { ssh $RemoteHost "cd $RemoteDir; docker compose ps --format '{{.Service}}\t{{.Status}}'" }
    Invoke-Step "health" { ssh $RemoteHost "for i in 1 2 3 4 5 6 7 8 9 10; do curl -fsS http://127.0.0.1:8095/healthz && exit 0; sleep 2; done; exit 1" }
    Write-Output ""
    Write-Output "deployed $sha"
} finally { Pop-Location }
