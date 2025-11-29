from typing import Optional, Dict, Any
import socket


def whois_lookup_domain(domain: str) -> Optional[Dict[str, Any]]:
    """
    TEMPORARY: WHOIS disabled to avoid noisy network errors.
    Always returns None so the rest of the pipeline keeps working.
    """
    return None


def ip_reverse_dns(ip: str) -> Optional[str]:
    """
    Still optionally try reverse DNS (local resolver only).
    This is usually quiet and non-fatal.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None

