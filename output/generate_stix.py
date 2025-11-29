from datetime import datetime
from pathlib import Path
import json

from stix2 import Indicator, Bundle

from database.db import get_recent_iocs

# Where to write the STIX bundle
OUTPUT_PATH = "output/stix/latest_bundle.json"

# Limit how many indicators we export per bundle
MAX_OBJECTS = 2000


def ioc_to_pattern(ioc_type: str, value: str) -> str | None:
    """
    Convert our simple IOC types into STIX patterns.

    Hash handling is based on length:
      - 32  hex chars -> MD5
      - 40  hex chars -> SHA-1
      - 64  hex chars -> SHA-256

    Anything else is ignored for STIX (we still keep it in the DB,
    just don't export it as an Indicator).
    """
    if ioc_type == "ip":
        # assume IPv4 for now
        return f"[ipv4-addr:value = '{value}']"

    if ioc_type == "domain":
        return f"[domain-name:value = '{value}']"

    if ioc_type == "url":
        return f"[url:value = '{value}']"

    if ioc_type == "hash":
        v = value.strip()
        length = len(v)

        if length == 32:
            algo = "MD5"
        elif length == 40:
            algo = "SHA-1"
        elif length == 64:
            algo = "SHA-256"
        else:
            # hash length not recognised; skip it for STIX
            return None

        return f"[file:hashes.'{algo}' = '{v}']"

    return None


def safe_parse_time(ts: str | None) -> datetime:
    """
    Parse ISO timestamp from DB; fall back to now() on failure.
    """
    if not ts:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.utcnow()


def generate_stix_bundle() -> None:
    """
    Read recent IOCs from the DB and generate a STIX 2.1 bundle
    containing Indicator objects.

    Any IOC which can't be expressed cleanly in STIX (e.g. weird hash
    lengths) is skipped for the bundle, but kept in the DB.
    """
    rows = get_recent_iocs(limit=MAX_OBJECTS)
    indicators: list[Indicator] = []

    for row in rows:
        # row schema: (id, type, value, source, enrichment_json, first_seen)
        _, ioc_type, value, source, enrichment_json, first_seen = row

        pattern = ioc_to_pattern(ioc_type, value)
        if not pattern:
            # unsupported type or bad hash length
            continue

        valid_from = safe_parse_time(first_seen)

        description_parts = [f"Source: {source}"]

        if enrichment_json:
            try:
                enr = json.loads(enrichment_json)
                if enr:
                    # keep it simple; just embed a stringified version
                    description_parts.append(f"Enrichment: {enr}")
            except Exception:
                # ignore bad JSON
                pass

        description = "; ".join(description_parts)

        try:
            ind = Indicator(
                name=f"{ioc_type} indicator",
                pattern_type="stix",
                pattern=pattern,
                valid_from=valid_from,
                description=description,
            )
            indicators.append(ind)
        except Exception as e:
            # if any single indicator is weird, skip it rather than fail the bundle
            print(f"[STIX] Skipping IOC {value!r} ({ioc_type}) due to error: {e}")
            continue

    # allow_custom=True prevents STIX from choking on minor extra fields
    bundle = Bundle(objects=indicators, allow_custom=True)

    out_path = Path(OUTPUT_PATH)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        f.write(bundle.serialize(pretty=True))

    print(f"[STIX] Wrote {len(indicators)} indicators to {OUTPUT_PATH}")


if __name__ == "__main__":
    generate_stix_bundle()
