NYK-FIL Maritime E Training Inc.
Security Monitoring System
================================


OVERVIEW
--------
This system runs on ONE designated "host" PC. That PC:
  - Watches the inbox\ folder for F5 / Log360 export files
  - Stores all alerts in a local database (capstone.db)
  - Hosts the Grafana dashboard

Other staff members do NOT need to install anything.
They view the dashboard from their own PC's web browser,
over the office network.

All data is retained in capstone.db on the host PC,
regardless of who is viewing the dashboard.


INSTALLATION (one-time, ~2 minutes — host PC only)
--------------------------------------------------
1. On the chosen host PC, extract this ZIP anywhere.
   Recommended: C:\NYKFilWatcher

2. RIGHT-CLICK setup.bat and choose "Run as administrator".
   (Admin rights are needed once, to open the firewall
    port so other staff PCs can reach the dashboard.)

3. When it finishes, the host PC's browser opens at:
       http://localhost:3000

   First login:  admin / admin
   (You will be asked to set a new password.)

That's it on the host PC — Python and Grafana are bundled.


GIVING OTHER STAFF ACCESS
-------------------------
A. Find the host PC's IP address.
   The setup.bat script prints it at the end, e.g.:
       From other staff PCs: http://192.168.1.50:3000

   Or open Command Prompt on the host PC and run:
       ipconfig
   Look for "IPv4 Address" under your Wi-Fi or Ethernet
   adapter (something like 192.168.x.x or 10.x.x.x).

B. Create a Grafana account for each staff member.
   On the host PC (or from any browser logged in as admin):
       Administration  ->  Users and access  ->  Users
       ->  New user
   New users default to the "Viewer" role (read-only),
   which is what you want for most staff.
   Only admins can edit the dashboard.

C. Share the URL with staff:
       http://<host-pc-ip>:3000
   e.g. http://192.168.1.50:3000

   They open it in any browser (Chrome, Edge, Firefox)
   on a PC connected to the same office network,
   and log in with the account you created for them.


REQUIREMENTS FOR MULTI-STAFF ACCESS
-----------------------------------
- All staff PCs must be on the same office network
  (same Wi-Fi or LAN) as the host PC.
- The host PC must stay powered on and logged in
  during the hours staff need the dashboard.
- The host PC's IP should ideally be static (ask IT
  to reserve it on the router) so the URL doesn't
  change. If the IP changes, just share the new one.


DAILY USE
---------
- Drop F5 or Log360 export files (XML or JSON) into:
      <install-folder>\inbox\
  on the HOST PC.

  The watcher picks them up automatically, deduplicates
  alerts, applies severity priority, correlates F5 vulns
  with Log360 events, and updates the dashboard live.

- Successfully processed files are deleted by default
  (or moved to processed\ if KEEP_PROCESSED is enabled).

- Files that fail to parse go to failed\ for review.

- All alerts, vulnerabilities, and events are stored
  permanently in capstone.db on the host PC. Data is
  NOT lost when the dashboard is closed or when staff
  log out.


AUTO-START
----------
On the host PC, the watcher and Grafana are registered
as Task Scheduler tasks:
      NYKFilWatcher
      NYKFilGrafana
They start automatically every time the host PC logs in.


BACKING UP YOUR DATA
--------------------
The entire history is in a single file:
      <install-folder>\capstone.db
Copy this file to a backup location periodically
(USB drive, network share, etc.) to preserve history.


TROUBLESHOOTING
---------------
- Staff cannot reach the dashboard from their PC?
  1. Confirm they are on the same office network.
  2. On the host PC, try opening http://localhost:3000
     first — if that works, the service is running.
  3. Re-run setup.bat as Administrator on the host PC
     to re-add the firewall rule.
  4. Some office networks block inter-PC traffic
     ("client isolation"). Ask IT to allow PCs to
     reach the host PC on TCP port 3000.

- Grafana not loading on the host PC?
  Open Task Scheduler -> run NYKFilGrafana,
  or start manually:
      grafana\bin\grafana-server.exe --homepath grafana

- Watcher not picking up files?
  Open Task Scheduler -> run NYKFilWatcher.

- Forgot the admin password?
  On the host PC, from the install folder:
      grafana\bin\grafana-cli.exe --homepath grafana ^
          admin reset-admin-password <newpassword>

- Need to uninstall?
  Run on the host PC:
      schtasks /delete /tn "NYKFilWatcher" /f
      schtasks /delete /tn "NYKFilGrafana" /f
      netsh advfirewall firewall delete rule ^
          name="NYKFil Grafana Dashboard"
  Then delete the install folder.


SUPPORT
-------
Contact: [your contact info here]
