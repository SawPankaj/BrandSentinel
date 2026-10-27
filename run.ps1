param([switch]$SetupAdmin)
$ErrorActionPreference = 'Stop'
$bundled = Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
if (Test-Path -LiteralPath $bundled) { $pythonExe = $bundled } else {
  $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
  if (-not $pythonCommand) { throw 'Python 3.10+ is required. Install Python and add it to PATH.' }
  $pythonExe = $pythonCommand.Source
}
& $pythonExe -c "import cryptography, pypdf, docx, pptx" 2>$null
if ($LASTEXITCODE -ne 0) {
  Write-Host 'Installing the packages from requirements.txt...'
  & $pythonExe -m pip install -r (Join-Path $PSScriptRoot 'backend/requirements.txt')
  if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
}
if ($SetupAdmin) {
  & $pythonExe (Join-Path $PSScriptRoot 'backend/server.py') setup-admin
} else {
  Write-Host 'BrandSentinel: http://127.0.0.1:8765'
  Write-Host 'Press Ctrl+C to stop the server.'
  & $pythonExe (Join-Path $PSScriptRoot 'backend/server.py') serve
}
