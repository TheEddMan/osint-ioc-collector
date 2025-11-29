import os
from typing import Optional, Dict, Any

try:
    from vt import Client
except ImportError:
    Client = None


VT_API_KEY = os.getenv("VT_API_KEY")


def vt_lookup_hash(file_hash: str) -> Optional[Dict[str, Any]]:
    """Lookup a file hash in VirusTotal. Returns None if VT not configured."""
    if not Client or not VT_API_KEY:
        return None

    try:
        with Client(VT_API_KEY) as client:
            obj = client.get_object(f"/files/{file_hash}")
            return {
                "vt_last_analysis_malicious": obj.last_analysis_stats.get("malicious", 0),
                "vt_last_analysis_suspicious": obj.last_analysis_stats.get("suspicious", 0),
                "vt_type": obj.type_description,
            }
    except Exception as e:
        print(f"[VT] Lookup failed for {file_hash}: {e}")
        return None
