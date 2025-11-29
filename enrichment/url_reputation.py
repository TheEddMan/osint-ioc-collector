from urllib.parse import urlparse
from typing import Dict, Any


def score_url(url: str) -> Dict[str, Any]:
    """
    Very basic local scoring: no external service required.
    You can extend this later with VT / other APIs.
    """
    parsed = urlparse(url)
    host = parsed.netloc or ""
    path = parsed.path or ""

    score = 0
    reasons = []

    if any(tld in host for tld in (".ru", ".cn", ".tk", ".top", ".xyz")):
        score += 2
        reasons.append("suspicious_tld")

    if len(host) > 25:
        score += 1
        reasons.append("long_hostname")

    if any(x in path.lower() for x in ("login", "verify", "update", "secure")):
        score += 1
        reasons.append("phishy_path_keyword")

    if url.count("@") > 0:
        score += 1
        reasons.append("has_@")

    return {
        "local_score": score,
        "local_reasons": reasons,
    }

