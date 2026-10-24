$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Build on Windows 11 x64; PyInstaller does not cross-compile.' }
Set-Location (Split-Path $PSScriptRoot -Parent)
py -3.12 -m venv .venv
if ($LASTEXITCODE) { throw 'Python 3.12 x64 is required on the build machine.' }
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt -c requirements.lock
if ($LASTEXITCODE) { throw 'Dependency installation failed' }
& .\.venv\Scripts\python.exe -m pytest -q
if ($LASTEXITCODE) { throw 'Tests failed' }
& .\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean --onefile --name WPA2RecoveryLab --add-data 'wpa2lab/static;wpa2lab/static' launcher.py
if ($LASTEXITCODE) { throw 'Packaging failed' }
$out = 'dist/WPA2-Recovery-Lab-Pro'
New-Item -ItemType Directory -Force $out, "$out/data", "$out/reports" | Out-Null
Copy-Item dist/WPA2RecoveryLab.exe, START.bat -Destination $out
Copy-Item README.md "$out/README.txt"
Get-FileHash "$out/WPA2RecoveryLab.exe" -Algorithm SHA256 | Format-List
Write-Host "Built $out. Run the Windows acceptance checks in README.txt before distribution."
