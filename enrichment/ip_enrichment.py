import requests
from typing import Optional, Dict, Any

IP_API_URL = "http://ip-api.com/json/"


def enrich_ip_basic(ip: str) -> Optional[Dict[str, Any]]:
    """
    GeoIP + ASN/ISP using ip-api.com (no key, free, but rate-limited).
    """
    try:
        resp = requests.get(IP_API_URL + ip, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            return None

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
        print(f"[IP-API] Failed for {ip}: {e}")
        return None
