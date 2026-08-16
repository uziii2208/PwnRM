<#
.SYNOPSIS
    PwnRM Release Automation Script (Windows)

.DESCRIPTION
    Tự động hóa toàn bộ quy trình release:
      1. Bump version (bump_version.py)
      2. Tạo venv mới
      3. Build package
      4. Verify version + packaging
      5. Upload lên PyPI
      6. Xóa venv

.EXAMPLE
    .\release.ps1 1.0.3
    .\release.ps1 1.0.3 -DryRun
    .\release.ps1 1.0.3 -SkipCleanup
#>

param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidatePattern('^\d+\.\d+\.\d+([\w.\-+]+)?$')]
    [string]$Version,
    [switch]$DryRun,
    [switch]$SkipCleanup
)

$ErrorActionPreference = "Stop"

# ---- locate repo root: walk up until pyproject.toml found ----
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$ROOT = $SCRIPT_DIR
while ($ROOT -and -not (Test-Path (Join-Path $ROOT "pyproject.toml"))) {
    $parent = Split-Path -Parent $ROOT
    if ($parent -eq $ROOT) { $ROOT = $null } else { $ROOT = $parent }
}
if (-not $ROOT) {
    Write-Host "[!] Cannot find repo root (pyproject.toml) above $SCRIPT_DIR" -ForegroundColor Red
    exit 1
}
Set-Location $ROOT

$bumpScript = Join-Path $ROOT "bump_version.py"
if (-not (Test-Path $bumpScript)) { $bumpScript = Join-Path $SCRIPT_DIR "bump_version.py" }

# venv in %TEMP% so the repo is never polluted
$VENV_PATH  = Join-Path $env:TEMP "pwnrm_release_temp"
$venvPython = Join-Path $VENV_PATH "Scripts\python.exe"
$twineExe   = Join-Path $VENV_PATH "Scripts\twine.exe"
$distPath   = Join-Path $ROOT "dist"

# remember current version BEFORE bump (for DryRun rollback)
$oldVersion = $null
$vm = Select-String -Path (Join-Path $ROOT "pyproject.toml") -Pattern '^\s*version\s*=\s*"([^"]+)"'
if ($vm) { $oldVersion = $vm.Matches[0].Groups[1].Value }

$script:rolledBack = $false

function Write-Step($msg) { Write-Host ""; Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[!] $msg" -ForegroundColor Red; throw $msg }

function Cleanup {
    if ($SkipCleanup) {
        Write-Warn "SkipCleanup set - keeping venv at $VENV_PATH"
        return
    }
    Write-Step "Cleanup - deleting temporary venv"
    if (Test-Path $VENV_PATH) {
        Remove-Item -Recurse -Force $VENV_PATH -ErrorAction SilentlyContinue
        Write-Ok "Venv deleted"
    }
}

function Rollback {
    if ($script:rolledBack) { return }
    $script:rolledBack = $true
    if (-not $oldVersion) {
        Write-Warn "Cannot rollback - old version unknown"
        return
    }
    Write-Step "DryRun rollback - restoring version $oldVersion"
    & python $bumpScript $oldVersion | Out-Null
    Write-Ok "Version strings + artifacts restored to $oldVersion"
}

trap {
    Write-Host ""
    Write-Host "[!] Release FAILED: $_" -ForegroundColor Red
    if ($DryRun) { Rollback }
    Cleanup
    exit 1
}

Write-Host "========================================" -ForegroundColor Magenta
Write-Host "  PwnRM Release Automation (Windows)" -ForegroundColor Magenta
Write-Host "  Target version: $Version  (repo root: $ROOT)" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta

# ---- Step 1: bump version ----
Write-Step "Step 1/6: Bumping version to $Version"
if (-not (Test-Path $bumpScript)) { Write-Err "bump_version.py not found" }
& python $bumpScript $Version
if ($LASTEXITCODE -ne 0) { Write-Err "bump_version.py failed" }
Write-Ok "Version bumped successfully"

# ---- Step 2: fresh venv + activate ----
Write-Step "Step 2/6: Creating fresh virtual environment (in TEMP)"
if (Test-Path $VENV_PATH) {
    Write-Warn "Venv already exists - removing"
    Remove-Item -Recurse -Force $VENV_PATH
}
& python -m venv $VENV_PATH
if ($LASTEXITCODE -ne 0) { Write-Err "Failed to create venv" }
if (-not (Test-Path $venvPython)) { Write-Err "venv python not found at $venvPython" }
# "activate" for this session: prepend venv Scripts to PATH
$env:PATH = "$VENV_PATH\Scripts;" + $env:PATH
Write-Ok "Venv created + activated (PATH) at $VENV_PATH"

# ---- Step 3: build tools + build ----
Write-Step "Step 3/6: Installing build tools and building package"
# python -m pip (NOT pip.exe) to avoid the Windows "To modify pip" error
& $venvPython -m pip install --upgrade -q pip setuptools wheel
if ($LASTEXITCODE -ne 0) { Write-Warn "pip self-upgrade failed (non-fatal) - continuing" }
& $venvPython -m pip install -q build twine
if ($LASTEXITCODE -ne 0) { Write-Err "Failed to install build tools" }

Write-Step "Cleaning old build artifacts"
foreach ($dir in @("dist", "build", "src\pwnrm.egg-info")) {
    $p = Join-Path $ROOT $dir
    if (Test-Path $p) {
        Remove-Item -Recurse -Force $p
        Write-Ok "Deleted $dir"
    }
}

Write-Step "Building package from $ROOT"
& $venvPython -m build
if ($LASTEXITCODE -ne 0) { Write-Err "Build failed" }

$wheel   = Get-ChildItem -Path $distPath -Filter "pwnrm-$Version-py3-none-any.whl" -ErrorAction SilentlyContinue
$tarball = Get-ChildItem -Path $distPath -Filter "pwnrm-$Version.tar.gz" -ErrorAction SilentlyContinue
if (-not $wheel -or -not $tarball) { Write-Err "Build artifacts not found for version $Version" }
Write-Ok "Build successful"
Write-Ok ("  Wheel   : " + $wheel.Name)
Write-Ok ("  Tarball : " + $tarball.Name)

# ---- Step 4: verify ----
Write-Step "Step 4/6: Verifying version in built package"
& $venvPython -m pip install -q $wheel.FullName
if ($LASTEXITCODE -ne 0) { Write-Err "Failed to install wheel" }

$pycheck = "import pwnrm,sys; from pathlib import Path; t=sys.argv[1]; " +
           "assert pwnrm.__version__==t, pwnrm.__version__; " +
           "p=Path(pwnrm.__file__).parent/'resources'/'adtriage.ps1'; " +
           "assert p.exists(); " +
           "print('[OK] pwnrm v'+pwnrm.__version__+' verified, adtriage.ps1 '+str(p.stat().st_size)+' bytes')"
& $venvPython -c $pycheck $Version
if ($LASTEXITCODE -ne 0) { Write-Err "Version or packaging verification failed" }
Write-Ok "All verifications passed"

# ---- Step 5: upload ----
Write-Step "Step 5/6: Upload to PyPI"
if ($DryRun) {
    Write-Warn "DryRun mode - skipping PyPI upload"
}
else {
    Write-Warn "Twine will prompt for your API token (username: __token__)"
    $distFiles = Get-ChildItem -Path $distPath -File | Select-Object -ExpandProperty FullName
    & $twineExe upload $distFiles
    if ($LASTEXITCODE -ne 0) { Write-Err "PyPI upload failed" }
    Write-Ok "Successfully uploaded to PyPI"
    Write-Ok ("View at: https://pypi.org/project/pwnrm/" + $Version + "/")
}

# ---- Step 6: rollback (DryRun) + cleanup ----
if ($DryRun) { Rollback }
Cleanup

Write-Host "========================================" -ForegroundColor Green
Write-Host "  Release Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ("Version   : " + $Version) -ForegroundColor Cyan
Write-Host ("Artifacts : " + $distPath) -ForegroundColor Cyan
if ($DryRun) {
    Write-Host ("Rolled back to: " + $oldVersion + " (DryRun)") -ForegroundColor Yellow
} else {
    Write-Host ("PyPI      : https://pypi.org/project/pwnrm/" + $Version) -ForegroundColor Cyan
}
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. git add -A"
Write-Host ("  2. git commit -m 'release: v" + $Version + "'")
Write-Host ("  3. git tag v" + $Version)
Write-Host "  4. git push origin master --tags"
Write-Host ("  5. Create GitHub Release for v" + $Version)
Write-Host ""
Write-Host "ENJOY YOUR MEAL!" -ForegroundColor Magenta