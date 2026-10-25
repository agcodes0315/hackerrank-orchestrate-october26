# Run this FROM THE ORIGINAL HACKERRANK REPO ROOT after extracting the ZIP elsewhere.
# Usage: .\INSTALL.ps1 -SourceFolder "C:\path\to\ghosttrace_unified"
param([Parameter(Mandatory=$true)][string]$SourceFolder)
if (!(Test-Path "dataset/deletion_requests.csv")) { throw "Run from the original repo root with dataset/ present." }
if (!(Test-Path "$SourceFolder/code/ghosttrace.py")) { throw "SourceFolder must be the extracted ghosttrace_unified folder." }
Copy-Item "$SourceFolder/code/*" -Destination "code" -Recurse -Force
Write-Host "Unified source files copied into code/. Dataset unchanged."
python code/ghosttrace.py tests
python code/ghosttrace.py all
