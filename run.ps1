# run.ps1 - Install dependencies and start Phishield server
# Usage: Right-click -> Run with PowerShell, or .\run.ps1 in PowerShell

Set-StrictMode -Version Latest

function Get-NodePath {
  $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
  if ($nodeCmd) {
    return $nodeCmd.Source
  }

  $candidates = @(
    "$env:ProgramFiles\nodejs\node.exe",
    "$env:ProgramFiles(x86)\nodejs\node.exe",
    "$env:LOCALAPPDATA\Programs\nodejs\node.exe"
  )

  foreach ($candidate in $candidates) {
    if (Test-Path $candidate) {
      return $candidate
    }
  }

  return $null
}

function Get-NpmPath {
  $npmCmd = Get-Command npm -ErrorAction SilentlyContinue
  if ($npmCmd) {
    return $npmCmd.Source
  }

  $nodePath = Get-NodePath
  if ($nodePath) {
    $nodeDir = Split-Path $nodePath
    $possible = @(
      (Join-Path $nodeDir 'npm.cmd'),
      (Join-Path $nodeDir 'npm.ps1')
    )

    foreach ($path in $possible) {
      if (Test-Path $path) {
        return $path
      }
    }
  }

  return $null
}

$nodePath = Get-NodePath
if (-not $nodePath) {
  Write-Host "Node.js not found. Please install Node.js from https://nodejs.org/ or run: winget install OpenJS.NodeJS" -ForegroundColor Yellow
  exit 1
}

$npmPath = Get-NpmPath
if (-not $npmPath) {
  Write-Host "npm not found. Please install Node.js with npm or verify your installation." -ForegroundColor Yellow
  exit 1
}

Write-Host "Installing npm dependencies..." -ForegroundColor Cyan
& "$npmPath" install --force
if ($LASTEXITCODE -ne 0) {
  Write-Host "npm install failed. See output above." -ForegroundColor Red
  exit $LASTEXITCODE
}

$port = $env:PORT
if (-not $port) { $port = 3000 }

Write-Host "Starting server (node server.js) on port $port..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $nodePath -ArgumentList 'server.js' -WorkingDirectory (Split-Path -Path $MyInvocation.MyCommand.Path) -WindowStyle Normal -PassThru
Start-Sleep -Seconds 1

$addr = "http://localhost:$port"
Write-Host "Opening $addr in default browser..." -ForegroundColor Green
Start-Process $addr

Write-Host "Server process started (PID: $($proc.Id))." -ForegroundColor Green
Write-Host "To stop the server: Stop-Process -Id $($proc.Id)" -ForegroundColor Yellow

# Optionally wait for the server process to exit before script returns
# Wait-Process -Id $proc.Id
