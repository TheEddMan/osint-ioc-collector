from datetime import datetime
import json

from stix2 import Indicator, Bundle

from database.db import get_recent_iocs


def ioc_to_stix_indicator(ioc_row):
    """
    ioc_row = (id, type, value, source, enrichment_json, first_seen)
    """
    _, ioc_type, value, source, enrichment_json, first_seen = ioc_row

    pattern_map = {
        "ip": f"[ipv4-addr:value = '{value}']",
        "domain": f"[domain-name:value = '{value}']",
        "url": f"[url:value = '{value}']",
        "hash": f"[file:hashes.'SHA-256' = '{value}']",
    }

    pattern = pattern_map.get(ioc_type)
    if not pattern:
        return None

    try:
        enrichment = json.loads(enrichment_json or "{}")
    except json.JSONDecodeError:
        enrichment = {}

    ind = Indicator(
        name=f"OSINT {ioc_type} from {source}",
        description=f"IOC collected by Raspberry Pi OSINT Harvester from {source}",
        pattern=pattern,
        pattern_type="stix",
        created=datetime.utcnow(),
        labels=["osint", "raspberry-pi", source],
        custom_properties={
            "x_osint_enrichment": enrichment,
            "x_first_seen": first_seen,
        }
    )
    return ind


def generate_stix_bundle(limit: int = 200, output_path: str = "output/stix/latest_bundle.json"):
    rows = get_recent_iocs(limit=limit)
    indicators = []

    for row in rows:
        ind = ioc_to_stix_indicator(row)
        if ind:
            indicators.append(ind)

    bundle = Bundle(objects=indicators)
    with open(output_path, "w") as f:
        f.write(str(bundle))
    print(f"[+] STIX bundle written to {output_path}")


if __name__ == "__main__":
    generate_stix_bundle()
