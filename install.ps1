# AEON Windows Installer
# Usage: irm https://raw.githubusercontent.com/aeon-lang/aeon/main/install.ps1 | iex
#
# Or manually: powershell -ExecutionPolicy Bypass -File install.ps1

$ErrorActionPreference = "Stop"

$AEON_VERSION = if ($env:AEON_VERSION) { $env:AEON_VERSION } else { "latest" }
$AEON_REPO = "https://github.com/aeon-lang/aeon.git"
$AEON_INSTALL_DIR = if ($env:AEON_INSTALL_DIR) { $env:AEON_INSTALL_DIR } else { "$env:USERPROFILE\.aeon" }

function Write-Info($msg)  { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err($msg)   { Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

# ── Check Python ────────────────────────────────────
function Test-Python {
    try {
        $version = & python --version 2>&1
        if ($version -match "Python 3\.(\d+)") {
            $minor = [int]$Matches[1]
            if ($minor -ge 10) {
                Write-Ok "Python $version found"
                return $true
            }
        }
    } catch {}

    try {
        $version = & python3 --version 2>&1
        if ($version -match "Python 3\.(\d+)") {
            $minor = [int]$Matches[1]
            if ($minor -ge 10) {
                Write-Ok "Python $version found"
                return $true
            }
        }
    } catch {}

    return $false
}

# ── Install Python ──────────────────────────────────
function Install-Python {
    Write-Info "Python 3.10+ not found."

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Info "Installing Python via winget..."
        winget install Python.Python.3.11 --accept-package-agreements --accept-source-agreements
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Info "Installing Python via Chocolatey..."
        choco install python311 -y
    } elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
        Write-Info "Installing Python via Scoop..."
        scoop install python
    } else {
        Write-Err "No package manager found. Please install Python 3.11+ from https://python.org"
    }

    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}

# ── Check Git ───────────────────────────────────────
function Test-Git {
    if (Get-Command git -ErrorAction SilentlyContinue) {
        return $true
    }

    Write-Info "Installing git..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install Git.Git --accept-package-agreements --accept-source-agreements
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        choco install git -y
    } elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
        scoop install git
    } else {
        Write-Err "Please install Git from https://git-scm.com"
    }

    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    return $true
}

# ── Install AEON ────────────────────────────────────
function Install-Aeon {
    Write-Info "Installing AEON to $AEON_INSTALL_DIR..."

    if (Test-Path $AEON_INSTALL_DIR) {
        Write-Info "Updating existing installation..."
        Push-Location $AEON_INSTALL_DIR
        git pull --quiet
        Pop-Location
    } else {
        git clone --quiet $AEON_REPO $AEON_INSTALL_DIR
    }

    Push-Location $AEON_INSTALL_DIR

    if ($AEON_VERSION -ne "latest") {
        git checkout "v$AEON_VERSION" 2>$null
        if ($LASTEXITCODE -ne 0) { git checkout $AEON_VERSION }
    }

    # Create virtual environment
    Write-Info "Creating virtual environment..."
    python -m venv "$AEON_INSTALL_DIR\.venv"
    & "$AEON_INSTALL_DIR\.venv\Scripts\Activate.ps1"

    # Install dependencies
    Write-Info "Installing dependencies..."
    pip install --quiet --upgrade pip
    pip install --quiet -e $AEON_INSTALL_DIR
    try { pip install --quiet z3-solver llvmlite } catch { Write-Warn "Optional deps (z3/llvmlite) failed; core features still work" }

    deactivate
    Pop-Location
}

# ── Set up PATH ─────────────────────────────────────
function Setup-Path {
    # Create wrapper script
    $binDir = "$env:USERPROFILE\.local\bin"
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null

    $wrapperContent = @"
@echo off
call "$AEON_INSTALL_DIR\.venv\Scripts\activate.bat"
python -m aeon.cli %*
"@
    Set-Content -Path "$binDir\aeon.cmd" -Value $wrapperContent

    # Add to user PATH
    $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$binDir*") {
        [System.Environment]::SetEnvironmentVariable("Path", "$binDir;$userPath", "User")
        Write-Info "Added $binDir to user PATH"
    }

    $env:Path = "$binDir;$env:Path"
}

# ── Main ────────────────────────────────────────────
Write-Host ""
Write-Host "====================================" -ForegroundColor Magenta
Write-Host "     AEON Installer v0.3.0          " -ForegroundColor Magenta
Write-Host "  AI-Native Formal Verification     " -ForegroundColor Magenta
Write-Host "====================================" -ForegroundColor Magenta
Write-Host ""

Test-Git | Out-Null

if (-not (Test-Python)) {
    Install-Python
    if (-not (Test-Python)) {
        Write-Err "Python installation failed"
    }
}

Install-Aeon
Setup-Path

Write-Host ""
Write-Host "====================================" -ForegroundColor Green
Write-Host " AEON installed successfully!" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Verify a file:  aeon check your_code.py --deep-verify"
Write-Host "  Start API:      python -m aeon.api_server --port 8000"
Write-Host "  Run tests:      aeon test --all"
Write-Host ""
Write-Host "  Supported: Python, Java, JavaScript, TypeScript,"
Write-Host "             Go, Rust, C/C++, Ruby"
Write-Host ""
Write-Host "  Restart your terminal to use the 'aeon' command." -ForegroundColor Yellow
Write-Host ""
