$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
function Find-Python {
    foreach ($candidate in @('py', 'python', 'python3')) {
        if (Get-Command $candidate -ErrorAction SilentlyContinue) {
            try {
                & $candidate -c "import sys; sys.exit(sys.version_info < (3,11))" 2>$null
                if ($LASTEXITCODE -eq 0) { return $candidate }
            } catch { continue }
        }
    }
    return $null
}
$probePython = Find-Python
if (-not $probePython) {
    Write-Host 'Python 3.11+ is missing / Python 3.11+ manque.'
    $answer = Read-Host 'Install Python 3.13 using winget? [y/N]'
    if ($answer -notin @('y', 'yes', 'o', 'oui')) { exit 2 }
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host 'Install Python from https://www.python.org/downloads/ then reopen dpi-probe.cmd.'
        exit 2
    }
    & winget install --id Python.Python.3.13 --exact --source winget --interactive
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
    $probePython = Find-Python
    if (-not $probePython) {
        Write-Host 'Python installed. Close this window and reopen dpi-probe.cmd.'
        exit 2
    }
}
& $probePython bootstrap.py
exit $LASTEXITCODE
