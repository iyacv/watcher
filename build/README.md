# Build the client bundle

## Prerequisites (dev machine only)
- Windows
- Python 3.10+ on PATH (used to run pip during the build)
- Internet access (downloads Python embeddable, Grafana, plugin)

## Build
```powershell
powershell -ExecutionPolicy Bypass -File build\build.ps1
```

Output: `dist\NYKFilWatcher-<date>.zip` (~150–200 MB).

The first build downloads ~120 MB into `build\downloads\` and caches them; subsequent builds reuse the cache and finish in seconds.

## What's inside the ZIP
```
NYKFilWatcher\
  setup.bat              ← client double-clicks this
  CLIENT_README.txt
  watcher.py
  config.py
  parsers\, pipeline\, storage\, samples\
  python\                ← embedded Python 3.11 + watchdog + dotenv
  grafana\               ← portable Grafana + SQLite plugin pre-installed
  inbox\, processed\, failed\   (empty)
```

## What the client does
1. Extract anywhere (e.g. `C:\NYKFilWatcher`)
2. Double-click `setup.bat`
3. Browser opens to `http://localhost:3000`

No Python install, no Grafana install, no internet required on the client side.

## Re-test on dev
You can also run the same `setup.bat` against an extracted bundle locally to validate it before shipping:
```
Expand-Archive dist\NYKFilWatcher-<date>.zip C:\Temp\NYKFilTest
C:\Temp\NYKFilTest\setup.bat
```
