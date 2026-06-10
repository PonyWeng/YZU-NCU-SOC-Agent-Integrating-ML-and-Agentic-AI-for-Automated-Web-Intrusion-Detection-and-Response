"""
assistant/threat_intel.py
Unified threat intelligence interface.

Providers:
  - AbuseIPDB  : IP abuse score + report history (requires API key)
  - IPinfo     : Geolocation + ASN (free, no key required)
"""

import requests

from config import ABUSEIPDB_API_KEY

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
IPINFO_URL    = "https://ipinfo.io/{ip}/json"
TIMEOUT       = 8


def check_ip(ip: str) -> dict:
    """
    Unified IP reputation check.
    Returns a flat dict of human-readable key/value pairs
    suitable for direct display in LINE messages.
    """
    result = {}

    # ── AbuseIPDB ─────────────────────────────────────────────
    if ABUSEIPDB_API_KEY:
        try:
            resp = requests.get(
                ABUSEIPDB_URL,
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                result["Abuse Score"]   = f"{score}/100 ({'MALICIOUS' if score > 25 else 'Clean'})"
                result["Total Reports"] = data.get("totalReports", 0)
                last = data.get("lastReportedAt")
                result["Last Reported"] = last[:10] if last else "Never"
                result["Country"]       = data.get("countryCode", "?")
                result["ISP"]           = data.get("isp", "?")
                result["Usage Type"]    = data.get("usageType", "?")
            elif resp.status_code == 422:
                result["AbuseIPDB"] = "Invalid IP address"
            else:
                result["AbuseIPDB"] = f"Error {resp.status_code}"
        except Exception as e:
            result["AbuseIPDB"] = f"Unavailable ({e})"
    else:
        result["AbuseIPDB"] = "No API key — add ABUSEIPDB_API_KEY to .env"

    # ── IPinfo (no key needed for basic tier) ─────────────────
    try:
        resp = requests.get(IPINFO_URL.format(ip=ip), timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if "bogon" in data:
                result["Type"]     = "Private / Reserved IP"
            else:
                city    = data.get("city", "")
                region  = data.get("region", "")
                country = data.get("country", "")
                result["Location"]  = ", ".join(filter(None, [city, region, country])) or "?"
                result["Org / ASN"] = data.get("org", "?")
                result["Hostname"]  = data.get("hostname", "?")
                result["Timezone"]  = data.get("timezone", "?")
    except Exception:
        pass   # IPinfo is best-effort

    return result
