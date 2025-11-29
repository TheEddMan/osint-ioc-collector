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

# Limit how many of each IOC type we store per feed per run
MAX_PER_TYPE = 1000

# Public OSINT feeds
URLHAUS_TEXT_FEED = "https://urlhaus.abuse.ch/downloads/text/"
MALWAREBAZAAR_RECENT_API = "https://mb-api.abuse.ch/api/v1/"
PHISHTANK_CSV = "http://data.phishtank.com/data/online-valid.csv"

# ThreatFox (Abuse.ch) – requires API key in environment
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_AUTH_KEY = os.environ.get("THREATFOX_AUTH_KEY", "")
THREATFOX_DAYS = 1  # how many days back to request (1–7 supported)

# OTX (AlienVault) – optional, needs API key & user id to work
OTX_API_KEY = ""          # put your key here if you have one
OTX_USER_ID = ""          # your OTX user id / email
OTX_PULSE_SEARCH = "malware"   # query term


def process_iocs_from_text(text: str, source: str):
    """
    Run the generic IOC parser over arbitrary text and store results,
    with optional enrichment.
    """
    iocs = extract_iocs(text)
    print(
        f"[+] {source}: {len(iocs['ips'])} IPs, "
        f"{len(iocs['domains'])} domains, "
        f"{len(iocs['urls'])} URLs, "
        f"{len(iocs['hashes'])} hashes"
    )

    # Domains
    for d in iocs["domains"][:MAX_PER_TYPE]:
        whois_data = whois_lookup_domain(d)
        store_ioc("domain", d, source, whois_data)

    # IPs
    for ip in iocs["ips"][:MAX_PER_TYPE]:
        enr = enrich_ip_basic(ip)
        store_ioc("ip", ip, source, enr)

    # URLs
    for url in iocs["urls"][:MAX_PER_TYPE]:
        rep = score_url(url)
        store_ioc("url", url, source, rep)

    # Hashes
    for h in iocs["hashes"][:MAX_PER_TYPE]:
        vt = vt_lookup_hash(h)
        store_ioc("hash", h, source, vt)


# -------- URLHAUS (malware URLs/domains) --------

def collect_urlhaus():
    print(f"[+] Fetching URLHaus text feed @ {datetime.utcnow()} UTC")
    resp = requests.get(URLHAUS_TEXT_FEED, timeout=60)
    resp.raise_for_status()
    process_iocs_from_text(resp.text, "urlhaus_text")


# -------- THREATFOX (abuse.ch IOCs via API key) --------

def collect_threatfox():
    """
    Collect IOCs from ThreatFox using the authenticated API.

    Uses THREATFOX_AUTH_KEY from the environment.
    Stores up to MAX_PER_TYPE of each IOC category with enrichment,
    consistent with the other collectors.
    """
    if not THREATFOX_AUTH_KEY:
        print("[i] ThreatFox not configured (no THREATFOX_AUTH_KEY), skipping.")
        return

    print(f"[+] Fetching ThreatFox IOCs (last {THREATFOX_DAYS} day(s))")

    payload = {
        "query": "get_iocs",
        "days": THREATFOX_DAYS
    }

    headers = {
        "Auth-Key": THREATFOX_AUTH_KEY
    }

    try:
        resp = requests.post(
            THREATFOX_API_URL,
            json=payload,
            headers=headers,
            timeout=60
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[!] ThreatFox request failed: {e}")
        return

    if data.get("query_status") != "ok":
        print(f"[!] ThreatFox query_status not ok: {data.get('query_status')}")
        return

    entries = data.get("data", [])
    counts = {
        "ip": 0,
        "domain": 0,
        "url": 0,
        "hash": 0,
    }

    for item in entries:
        ioc_type = (item.get("ioc_type") or "").lower()
        value = item.get("ioc")
        if not value:
            continue

        # Map ThreatFox types to our categories
        if ioc_type in ("ip", "ipv4", "ipv6"):
            if counts["ip"] >= MAX_PER_TYPE:
                continue
            enr = enrich_ip_basic(value)
            store_ioc("ip", value, "threatfox", enr)
            counts["ip"] += 1

        elif ioc_type in ("domain", "hostname"):
            if counts["domain"] >= MAX_PER_TYPE:
                continue
            whois_data = whois_lookup_domain(value)
            store_ioc("domain", value, "threatfox", whois_data)
            counts["domain"] += 1

        elif ioc_type in ("url", "uri"):
            if counts["url"] >= MAX_PER_TYPE:
                continue
            rep = score_url(value)
            store_ioc("url", value, "threatfox", rep)
            counts["url"] += 1

        elif ioc_type in ("md5", "sha1", "sha256", "sha512", "imphash", "sha3_256"):
            if counts["hash"] >= MAX_PER_TYPE:
                continue
            vt = vt_lookup_hash(value)
            store_ioc("hash", value, "threatfox", vt)
            counts["hash"] += 1

        # Stop if we've hit limits for *all* categories
        if all(c >= MAX_PER_TYPE for c in counts.values()):
            break

    total = sum(counts.values())
    print(
        f"[+] ThreatFox: stored {total} IOCs "
        f"({counts['ip']} IPs, {counts['domain']} domains, "
        f"{counts['url']} URLs, {counts['hash']} hashes)"
    )


# -------- MALWAREBAZAAR (malware hashes) --------

def collect_malwarebazaar():
    print("[+] Fetching MalwareBazaar recent samples")
    payload = {"query": "get_recent", "selector": "time"}
    try:
        resp = requests.post(MALWAREBAZAAR_RECENT_API, data=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[!] MalwareBazaar request failed: {e}")
        return

    samples = data.get("data", [])
    count = 0
    for s in samples:
        sha256 = s.get("sha256_hash")
        if not sha256:
            continue
        vt = vt_lookup_hash(sha256)
        store_ioc("hash", sha256, "malwarebazaar", vt)
        count += 1
        if count >= MAX_PER_TYPE:
            break

    print(f"[+] MalwareBazaar: stored {count} hashes")


# -------- PHISHTANK (phishing URLs) --------

def collect_phishtank():
    print("[+] Fetching PhishTank CSV")
    try:
        resp = requests.get(PHISHTANK_CSV, timeout=60)
        resp.raise_for_status()
    except Exception as e:
        print(f"[!] PhishTank request failed: {e}")
        return

    f = io.StringIO(resp.text)
    reader = csv.DictReader(f)
    count = 0
    for row in reader:
        url = row.get("url")
        if not url:
            continue
        rep = score_url(url)
        store_ioc("url", url, "phishtank", rep)
        count += 1
        if count >= MAX_PER_TYPE:
            break

    print(f"[+] PhishTank: stored {count} URLs")


# -------- OTX (AlienVault pulses, optional) --------

def collect_otx_pulses():
    if not (OTX_API_KEY and OTX_USER_ID):
        print("[i] OTX not configured (no API key/user id), skipping.")
        return

    print("[+] Fetching OTX pulses search results")
    url = "https://otx.alienvault.com/api/v1/search/pulses"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    params = {"q": OTX_PULSE_SEARCH, "limit": 20}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[!] OTX request failed: {e}")
        return

    pulses = data.get("results", [])
    stored = 0

    for pulse in pulses:
        indicators = pulse.get("indicators", [])
        for ind in indicators:
            ind_type = ind.get("type")
            ind_val = ind.get("indicator")
            if not ind_val:
                continue

            src = "otx"

            if ind_type in ("IPv4", "IPv6"):
                enr = enrich_ip_basic(ind_val)
                store_ioc("ip", ind_val, src, enr)
            elif ind_type == "domain":
                whois_data = whois_lookup_domain(ind_val)
                store_ioc("domain", ind_val, src, whois_data)
            elif ind_type == "URL":
                rep = score_url(ind_val)
                store_ioc("url", ind_val, src, rep)
            elif "hash" in (ind_type or "").lower():
                vt = vt_lookup_hash(ind_val)
                store_ioc("hash", ind_val, src, vt)

            stored += 1
            if stored >= MAX_PER_TYPE:
                break
        if stored >= MAX_PER_TYPE:
            break

    print(f"[+] OTX: stored {stored} indicators")


# -------- ORCHESTRATOR --------

def run_all_collectors():
    """
    Called from run_all.py
    """
    init_db()
    collect_urlhaus()
    collect_threatfox()
    collect_malwarebazaar()
    collect_phishtank()
    collect_otx_pulses()


if __name__ == "__main__":
    run_all_collectors()
