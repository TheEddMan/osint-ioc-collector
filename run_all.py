from collector.feed_collector import run_all_collectors
from output.generate_stix import generate_stix_bundle
from database.db import init_db


def main():
    print("[+] Initialising database (if needed)")
    init_db()

    print("[+] Running collectors")
    run_all_collectors()

    print("[+] Generating STIX bundle")
    generate_stix_bundle()


if __name__ == "__main__":
    main()
