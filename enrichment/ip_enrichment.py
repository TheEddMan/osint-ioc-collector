import requests
from typing import Optional, Dict, Any

IP_API_URL = "http://ip-api.com/json/"

# Limit how many IP lookups we do in a single run
LOOKUP_LIMIT = 40
_lookup_count = 0


def enrich_ip_basic(ip: str) -> Optional[Dict[str, Any]]:
    """
    GeoIP + ASN/ISP using ip-api.com (no key, free, but rate-limited).
    We only do a limited number of lookups per run to avoid 429 errors.
    """
    global _lookup_count

    # If we've hit our limit, skip further lookups
    if _lookup_count >= LOOKUP_LIMIT:
        return None

    try:
        resp = requests.get(IP_API_URL + ip, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            return None

        _lookup_count += 1

        return {
            "country": data.get("country"),
            "countryCode": data.get("countryCode"),
            "city": data.get("city"),
            "asn": data.get("as"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
        }
    except Exception as e:
        # Comment this out if you want total silence:
        # print(f"[IP-API] Failed for {ip}: {e}")
        return None

