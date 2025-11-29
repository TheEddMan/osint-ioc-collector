import csv
import io
import json
from datetime import datetime

import requests

from parser.ioc_parser import extract_iocs
from database.db import store_ioc, init_db
from enrichment.whois_lookup import whois_lookup_domain
from enrichment.vt_lookup import vt_lookup_hash
from enrichment.ip_enrichment import enrich_ip_basic
from enrichment.url_reputation import score_url


# ==== CONFIG / API KEYS (optional) ====
OTX_API_KEY = ""          # put your key here if you have one
OTX_USER_ID = ""          # your OTX user id / email
OTX_PULSE_SEARCH = "malware"   # query term

URLHAUS_TEXT_FEED = "https://urlhaus.abuse.ch/downloads/text/"
THREATFOX_RECENT_API = "https://threatfox-api.abuse.ch/api/v1/"
MALWAREBAZAAR_RECENT_API = "https://mb-api.abuse.ch/api/v1/"
PHISHTANK_CSV = "http://data.phishtank.com/data/online-valid.csv"  # public CSV


# ====== COMMON PROCESSOR ======

def process_iocs_from_text(text: str, source: str):
    iocs = extract_iocs(text)
    print(f"[+] {source}: {len(iocs['ips'])} IPs, "
          f"{len(iocs['domains'])} domains, "
          f"{len(iocs['urls'])} URLs, "
          f"{len(iocs['hashes'])} hashes")

    # domains
    for d in iocs["domains"]:
        whois_data = whois_lookup_domain(d)
        store_ioc("domain", d, source, whois_data)

    # ips
    for ip in iocs["ips"]:
        enr = enrich_ip_basic(ip)
        store_ioc("ip", ip, source, enr)

    # urls
    for url in iocs["urls"]:
        rep = score_url(url)
        store_ioc("url", url, source, rep)

    # hashes
    for h in iocs["hashes"]:
        vt = vt_lookup_hash(h)
        store_ioc("hash", h, source, vt)


# ====== URLHAUS (existing) ======

def collect_urlhaus():
    print(f"[+] Fetching URLHaus text feed @ {datetime.utcnow()} UTC")
    resp = requests.get(URLHAUS_TEXT_FEED, timeout=60)
    resp.raise_for_status()
    process_iocs_from_text(resp.text, "urlhaus_text")


# ====== THREATFOX (C2 infra / malware IOCs) ======

def collect_threatfox():
    print(f"[+] Fetching ThreatFox recent IOCs")
    payload = {"query": "get_iocs", "days": 1}
    resp = requests.post(THREATFOX_RECENT_API, json=payload, timeout=60)
    resp.raise_for_status()
    data = resp.json()

    if "data" not in data:
        print("[!] ThreatFox: no data field")
        return

    for entry in data["data"]:
        ioc_type = entry.get("ioc_type")
        ioc = entry.get("ioc")
        if not ioc:
            continue

        src = "threatfox"
        if ioc_type == "ip:port" or ioc_type == "ip":
            enr = enrich_ip_basic(ioc.split(":")[0])
            store_ioc("ip", ioc.split(":")[0], src, enr)
        elif ioc_type == "domain":
            whois_data = whois_lookup_domain(ioc)
            store_ioc("domain", ioc, src, whois_data)
        elif ioc_type == "url":
            rep = score_url(ioc)
            store_ioc("url", ioc, src, rep)
        elif ioc_type.startswith("sha"):
            vt = vt_lookup_hash(ioc)
            store_ioc("hash", ioc, src, vt)


# ====== MALWAREBAZAAR (hashes) ======

def collect_malwarebazaar():
    print("[+] Fetching MalwareBazaar recent samples")
    payload = {"query": "get_recent", "selector": "time"}
    resp = requests.post(MALWAREBAZAAR_RECENT_API, data=payload, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    samples = data.get("data", [])
    for s in samples:
        sha256 = s.get("sha256_hash")
        if not sha256:
            continue
        vt = vt_lookup_hash(sha256)
        store_ioc("hash", sha256, "malwarebazaar", vt)


# ====== PHISHTANK (phishing URLs) ======

def collect_phishtank():
    print("[+] Fetching PhishTank CSV")
    resp = requests.get(PHISHTANK_CSV, timeout=60)
    resp.raise_for_status()

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
        if count >= 500:  # don’t overload DB
            break

    print(f"[+] PhishTank: stored {count} URLs")


# ====== OTX (optional, needs API key & user id) ======

def collect_otx_pulses():
    if not (OTX_API_KEY and OTX_USER_ID):
        print("[i] OTX not configured, skipping.")
        return

    print("[+] Fetching OTX pulses search results")
    url = f"https://otx.alienvault.com/api/v1/search/pulses"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    params = {"q": OTX_PULSE_SEARCH, "limit": 20}
    resp = requests.get(url, headers=headers, params=params, timeout=60)
    resp.raise_for_status()
    data = resp.json()

    for pulse in data.get("results", []):
        for ind in pulse.get("indicators", []):
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
            elif "hash" in ind_type.lower():
                vt = vt_lookup_hash(ind_val)
                store_ioc("hash", ind_val, src, vt)


# ====== ORCHESTRATOR ======

def run_all_collectors():
    init_db()
    collect_urlhaus()
    collect_threatfox()
    collect_malwarebazaar()
    collect_phishtank()
    collect_otx_pulses()


if __name__ == "__main__":
    run_all_collectors()
