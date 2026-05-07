"""
Provision the Grafana SQLite data source for the capstone watcher.

Writes a provisioning YAML into Grafana's conf/provisioning/datasources/
folder, pointing at the local capstone.db. Run after the plugin is
installed; restart the Grafana service for the change to take effect.
"""
import pathlib
import shutil
import sys
import textwrap

DB_PATH = pathlib.Path(__file__).resolve().parent.parent / "capstone.db"


def main() -> int:
    cli = shutil.which("grafana-cli")
    if not cli:
        print("grafana-cli not found on PATH; skipping data source provisioning.")
        print("Install Grafana, ensure grafana-cli is on PATH, then re-run this script.")
        return 0

    grafana_home = pathlib.Path(cli).resolve().parent.parent
    prov_dir = grafana_home / "conf" / "provisioning" / "datasources"
    try:
        prov_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        print(f"ERROR: cannot write to {prov_dir}.")
        print("Re-run setup as Administrator.")
        return 1

    yaml = textwrap.dedent(f"""\
        apiVersion: 1

        datasources:
          - name: Capstone SQLite
            type: frser-sqlite-datasource
            access: proxy
            isDefault: true
            jsonData:
              path: {DB_PATH}
    """)
    target = prov_dir / "capstone-sqlite.yaml"
    target.write_text(yaml, encoding="utf-8")
    print(f"Wrote data source: {target}")
    print(f"  -> path: {DB_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
