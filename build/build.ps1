# build.ps1 — Builds the offline portable bundle for the client.
# Run on YOUR machine (with internet). Produces dist\NYKFilWatcher-<date>.zip.
#
# Architecture: cloud-only. Supabase = database, Grafana Cloud = dashboard.
# The client only runs the watcher locally — they drop log files into inbox\
# and the watcher pushes them to Supabase. No local Grafana, no firewall, no DB setup.
#
# The ZIP does NOT contain any DATABASE_URL or secrets. The client pastes the
# URL once when they run setup.bat. This keeps the ZIP safe to distribute by
# any channel (email, chat, shared drive) without leaking credentials.

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

$BUILD_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$REPO      = Split-Path -Parent $BUILD_DIR
$DOWNLOAD  = Join-Path $BUILD_DIR "downloads"
$DIST      = Join-Path $REPO "dist"
$STAGE     = Join-Path $DIST "NYKFilWatcher"

$PY_VER      = "3.11.9"
$PY_URL      = "https://www.python.org/ftp/python/$PY_VER/python-$PY_VER-embed-amd64.zip"
$GET_PIP_URL = "https://bootstrap.pypa.io/get-pip.py"

# ── Prep ────────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $DOWNLOAD,$DIST | Out-Null
if (Test-Path $STAGE) { Remove-Item -Recurse -Force $STAGE }
New-Item -ItemType Directory -Force -Path $STAGE | Out-Null

function Get-IfMissing($url, $out) {
    if (Test-Path $out) {
        Write-Host "  cached: $(Split-Path -Leaf $out)"
    } else {
        Write-Host "  downloading: $url"
        Invoke-WebRequest -Uri $url -OutFile $out
    }
}

# ── 1. Python embeddable ────────────────────────────────────────────────────
Write-Host "[1/4] Python $PY_VER embeddable"
$pyZip = Join-Path $DOWNLOAD "python-$PY_VER-embed.zip"
Get-IfMissing $PY_URL $pyZip
$pyDir = Join-Path $STAGE "python"
Expand-Archive $pyZip -DestinationPath $pyDir -Force

# Enable site-packages in the embeddable distribution
$pthFile = Get-ChildItem (Join-Path $pyDir "python*._pth") | Select-Object -First 1
$lines = Get-Content $pthFile.FullName
$lines = $lines | ForEach-Object { if ($_ -match '^\s*#\s*import\s+site') { 'import site' } else { $_ } }
if ($lines -notcontains 'Lib\site-packages') { $lines += 'Lib\site-packages' }
Set-Content -Path $pthFile.FullName -Value $lines -Encoding ASCII

# Bootstrap pip
$getPip = Join-Path $DOWNLOAD "get-pip.py"
Get-IfMissing $GET_PIP_URL $getPip
& "$pyDir\python.exe" $getPip --no-warn-script-location | Out-Null

# ── 2. Install Python dependencies ──────────────────────────────────────────
Write-Host "[2/4] Installing Python dependencies into bundled Python"
$reqFile = Join-Path $REPO "requirements.txt"
& "$pyDir\python.exe" -m pip install --no-warn-script-location -r $reqFile | Out-Null

# ── 3. Copy watcher source into the bundle ──────────────────────────────────
Write-Host "[3/4] Copying watcher source"
$excludeDirs  = @(
    "dist","build","downloads","__pycache__",
    "processed","failed","inbox",
    ".git",".venv",".vscode",".claude",
    "samples"
)
$excludeFiles = @(
    "*.pyc","*.zip","*.db","*.db-journal",
    ".env",".gitignore",
    "*.xlsx","*.xlsm","*.xml","*.json"   # any stray client log files at the repo root
)
$xdArgs = @()
foreach ($e in $excludeDirs) { $xdArgs += "/XD"; $xdArgs += (Join-Path $REPO $e) }
robocopy $REPO $STAGE /E /XF @excludeFiles @xdArgs /NFL /NDL /NJH /NJS /NP | Out-Null

# Whitelist the grafana JSON files we DO want — the broad *.json exclude above
# stripped them, so copy them back explicitly. We only want the postgres dashboard;
# the old SQLite dashboard.json is dead weight.
$grafanaDest = Join-Path $STAGE "grafana"
if (Test-Path (Join-Path $REPO "grafana")) {
    New-Item -ItemType Directory -Force $grafanaDest | Out-Null
    Copy-Item (Join-Path $REPO "grafana\dashboard.postgres.json") $grafanaDest -Force -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $REPO "grafana\datasource.yml")          $grafanaDest -Force -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $REPO "grafana\provision.py")            $grafanaDest -Force -ErrorAction SilentlyContinue
}

# Safety nets: delete anything sensitive or stale that somehow made it through.
$staleArtifacts = @(
    ".env", ".gitignore",
    "grafana\dashboard.json"                # old SQLite-era dashboard
)
foreach ($f in $staleArtifacts) {
    $p = Join-Path $STAGE $f
    if (Test-Path $p) { Remove-Item -Force $p }
}

# Empty inbox/processed/failed so the client starts clean
foreach ($d in @("inbox","processed","failed")) {
    $p = Join-Path $STAGE $d
    New-Item -ItemType Directory -Force $p | Out-Null
    Get-ChildItem $p -ErrorAction Ignore | Remove-Item -Recurse -Force
}

# ── 4. Zip ──────────────────────────────────────────────────────────────────
Write-Host "[4/4] Compressing bundle"
$stamp = Get-Date -Format "yyyyMMdd"
$out = Join-Path $DIST "NYKFilWatcher-$stamp.zip"
if (Test-Path $out) { Remove-Item $out }
Compress-Archive -Path "$STAGE\*" -DestinationPath $out -CompressionLevel Optimal

$sizeMB = [math]::Round((Get-Item $out).Length / 1MB, 1)
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════"
Write-Host "  Bundle ready:"
Write-Host "    $out"
Write-Host "    Size: $sizeMB MB"
Write-Host ""
Write-Host "  Client steps:"
Write-Host "    1. Extract the ZIP anywhere (e.g. C:\NYKFilWatcher)"
Write-Host "    2. Double-click setup.bat"
Write-Host "    3. Paste the DATABASE_URL when prompted (one-time)"
Write-Host "    4. Drop log files into inbox\"
Write-Host ""
Write-Host "  Send the client a chat message with the URL, e.g.:"
Write-Host "    Paste this when setup asks for DATABASE_URL:"
Write-Host "    postgresql://postgres.xxxx:PASSWORD@aws-...supabase.com:6543/postgres"
Write-Host "═══════════════════════════════════════════════════════"
