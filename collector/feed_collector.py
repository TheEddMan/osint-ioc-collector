import csv
import io
import os
from datetime import datetime
import requests

from parser.ioc_parser import extract_iocs
from database.db import store_ioc, init_db
from enrichment.whois_lookup import whois_lookup_domain
from enrichment.vt_lookup import vt_lookup_hash
from enrichment.ip_enrichment import enrich_ip_basic
from enrichment.url_reputation import score_url

MAX_PER_TYPE = 1000

URLHAUS_TEXT_FEED = "https://urlhaus.abuse.ch/downloads/text/"
MALWAREBAZAAR_RECENT_API = "https://mb-api.abuse.ch/api/v1/"
PHISHTANK_CSV = "http://data.phishtank.com/data/online-valid.csv"

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_AUTH_KEY = os.environ.get("THREATFOX_AUTH_KEY", "")
THREATFOX_DAYS = 1

OTX_API_KEY = ""
OTX_USER_ID = ""
OTX_PULSE_SEARCH = "malware"


def process_iocs_from_text(text: str, source: str):
    iocs = extract_iocs(text)
    print(f"[+] {source}: {len(iocs['ips'])} IPs, "
          f"{len(iocs['domains'])} domains, "
          f"{len(iocs['urls'])} URLs, "
          f"{len(iocs['hashes'])} hashes")

    for d in iocs["domains"][:MAX_PER_TYPE]:
        whois_data = whois_lookup_domain(d)
        store_ioc("domain", d, source, whois_data)

    for ip in iocs["ips"][:MAX_PER_TYPE]:
        enr = enrich_ip_basic(ip)
        store_ioc("ip", ip, source, enr)

    for url in iocs["urls"][:MAX_PER_TYPE]:
        rep = score_url(url)
        store_ioc("url", url, source, rep)

    for h in iocs["hashes"][:MAX_PER_TYPE]:
        vt = vt_lookup_hash(h)
        store_ioc("hash", h, source, vt)


def collect_urlhaus():
    print(f"[+] Fetching URLHaus text feed @ {datetime.utcnow()} UTC")
    resp = requests.get(URLHAUS_TEXT_FEED, timeout=60)
    resp.raise_for_status()
    process_iocs_from_text(resp.text, "urlhaus_text")


def collect_threatfox():
    if not THREATFOX_AUTH_KEY:
        print("[i] ThreatFox not configured (no THREATFOX_AUTH_KEY), skipping.")
        return

    print(f"[+] Fetching ThreatFox IOCs (last {THREATFOX_DAYS} day(s))")

    payload = {"query": "get_iocs", "days": THREATFOX_DAYS}
    headers = {"Auth-Key": THREATFOX_AUTH_KEY}

    try:
        resp = requests.post(THREATFOX_API_URL, json=payload, headers=headers, timeout=60)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[!] ThreatFox request failed: {e}")
        return

    if data.get("query_status") != "ok":
        print(f"[!] ThreatFox API error: {data.get('query_status')}")
        return

    entries = data.get("data", [])
    counts = {"ip": 0, "domain": 0, "url": 0, "hash": 0}

    for item in entries:
        ioc_type = (item.get("ioc_type") or "").lower()
        value = item.get("ioc")
        if not value:
            continue

        if ioc_type in ("ip", "ipv4", "ipv6"):
            if counts["ip"] < MAX_PER_TYPE:
                store_ioc("ip", value, "threatfox", enrich_ip_basic(value))
                counts["ip"] += 1

        elif ioc_type in ("domain", "hostname"):
            if counts["domain"] < MAX_PER_TYPE:
                store_ioc("domain", value, "threatfox", whois_lookup_domain(value))
                counts["domain"] += 1

        elif ioc_type in ("url", "uri"):
            if counts["url"] < MAX_PER_TYPE:
                store_ioc("url", value, "threatfox", score_url(value))
                counts["url"] += 1

        elif ioc_type in ("md5", "sha1", "sha256", "sha512", "imphash", "sha3_256"):
            if counts["hash"] < MAX_PER_TYPE:
                store_ioc("hash", value, "threatfox", vt_lookup_hash(value))
                counts["hash"] += 1

        if all(c >= MAX_PER_TYPE for c in counts.values()):
            break

    total = sum(counts.values())
    print(
        f"[+] ThreatFox: stored {total} IOCs "
        f"({counts['ip']} IPs, {counts['domain']} domains, "
        f"{counts['url']} URLs, {counts['hash']} hashes)"
    )


def collect_malwarebazaar():
    print("[+] Fetching MalwareBazaar rece
