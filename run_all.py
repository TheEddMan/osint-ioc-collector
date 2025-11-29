from collector.feed_collector import run_all_collectors
from output.generate_stix import generate_stix_bundle
from output.export_json import export_latest_iocs_json, export_counts_json
from database.db import init_db


def main():
    print("[+] Initialising database (if needed)")
    init_db()

    print("[+] Running collectors")
    run_all_collectors()

    print("[+] Generating STIX bundle")
    generate_stix_bundle()

    print("[+] Exporting JSON for static dashboard")
    export_latest_iocs_json(limit=300)
    export_counts_json(days=7)


if __name__ == "__main__":
    main()
