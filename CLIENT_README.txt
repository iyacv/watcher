NYK-FIL Maritime E Training Inc.
Security Monitoring System
================================


OVERVIEW
--------
This is a lightweight watcher that uploads your F5 and Log360
log exports to the central Supabase database. The Grafana
dashboard reads from that database and is hosted in the cloud
(URL provided by your administrator).

What this installer does:
  - Sets up a folder that watches for log files
  - Auto-starts every time you log in to Windows
  - Pushes every file you drop in to the shared database

You do NOT install Python, Grafana, or any database.
Everything needed is bundled. The database and dashboard
already exist online.


INSTALLATION (one-time, under 1 minute)
---------------------------------------
You should have received TWO things from your administrator:
  - This ZIP file (the installer)
  - A DATABASE_URL (a single line starting with "postgresql://")

1. Extract the ZIP anywhere on your PC.
   Recommended: C:\NYKFilWatcher

2. Double-click setup.bat
   (Just a normal double-click — no admin rights needed.)

3. When prompted, paste the DATABASE_URL your administrator
   sent you, then press Enter.

4. When it finishes, that's it. The watcher is running
   in the background and will start automatically every
   time you log in to Windows.

You only ever need to paste the URL once. After that,
re-running setup.bat reuses what you pasted.


DAILY USE
---------
Drop F5 or Log360 export files into:
    <install-folder>\inbox\

Supported file types:
  - .xml   (F5 ASM scan exports, Log360 XML)
  - .xlsx  (Log360 "All Events" Excel exports)
  - .json  (Log360 JSON exports)

The watcher picks them up automatically (within seconds),
parses them, deduplicates, and uploads to Supabase.

What happens to the file after processing:
  - Success     -> deleted from inbox (or moved to processed\
                   if KEEP_PROCESSED=true in .env)
  - Parse error -> moved to failed\ so you can review it


VIEWING THE DASHBOARD
---------------------
Open the Grafana Cloud URL provided by your administrator
in any web browser. Log in with the credentials given to you.

The dashboard is shared — everyone you give access to sees
the same data. You can view it from any PC, anywhere with
internet (it does NOT have to be on the office network).


CHECKING THAT IT'S WORKING
--------------------------
1. Drop one of your real F5 or Log360 export files into inbox\
2. Wait about 10 seconds — the file should disappear from inbox\
   (it was uploaded to Supabase and then deleted)
3. Open the Grafana dashboard. The new logs should appear in
   the panels within seconds.

If the file ends up in failed\ instead, something in the file
couldn't be parsed. Send the file in failed\ to your
administrator for review.


STOPPING / RESTARTING THE WATCHER
---------------------------------
Stop:
    schtasks /end /tn "NYKFilWatcher"

Start again:
    schtasks /run /tn "NYKFilWatcher"

Or open Task Scheduler from the Start menu, find "NYKFilWatcher"
in the list, and right-click to start/stop.


UNINSTALL
---------
1. Stop the auto-start:
       schtasks /delete /tn "NYKFilWatcher" /f
2. Delete the installation folder.

Nothing is left behind. No registry entries, no services,
no other system changes.


TROUBLESHOOTING
---------------
Files stay in inbox\ and never disappear:
  - Open Task Manager and check that "pythonw.exe" is running.
  - If not, double-click setup.bat again — it re-registers
    and starts the watcher.

Files end up in failed\:
  - The file format wasn't recognised or had bad data.
  - Open the file in failed\ and check the first few rows
    look like a normal Log360 / F5 export.
  - For xlsx files: the "All Events" sheet must have these
    columns in this order:
        Time, Log Source, Event ID, Display Name, Source, Severity

Dashboard doesn't show new data:
  - First check that files are disappearing from inbox\
    (that confirms the upload worked).
  - Refresh the Grafana dashboard in your browser.
  - Check the time range picker at the top right of the
    dashboard — if it's set to a narrow window, your new
    data may be outside it. Try "Last 24 hours".

Need to change the database connection:
  - Edit the .env file in this folder.
  - DATABASE_URL=postgresql://... is the line to change.
  - Restart the watcher (see above).


SUPPORT
-------
Contact: [your contact info here]
