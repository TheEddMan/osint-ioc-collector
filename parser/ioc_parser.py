import re
from typing import Dict, List


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extract basic IOCs from raw text."""
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

    # crude domain regex (ignores plain IPs)
    domains = re.findall(
        r'\b(?:(?!\d+\.)[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b',
        text
    )

    urls = re.findall(r'https?://[^\s"\']+', text)

    # MD5/SHA1/SHA256 (32–64 hex chars)
    hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)

    # de-duplicate
    return {
        "ips": sorted(set(ips)),
        "domains": sorted(set(domains)),
        "urls": sorted(set(urls)),
        "hashes": sorted(set(hashes)),
    }
