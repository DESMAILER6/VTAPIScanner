from urllib.parse import urlparse
import re

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "update", "billing",
    "wallet", "bank", "password", "signin", "confirm", "limited"
]


def analyze_url_heuristics(url: str) -> dict:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    findings = []

    if parsed.scheme != "https":
        findings.append("URL does not use HTTPS")

    if "@" in url:
        findings.append("URL contains @ symbol")

    if len(url) > 120:
        findings.append("URL is unusually long")

    if re.search(r"\d+\.\d+\.\d+\.\d+", host):
        findings.append("URL uses an IP address instead of a domain")

    if host.count("-") >= 3:
        findings.append("Domain contains many hyphens")

    keyword_hits = [word for word in SUSPICIOUS_WORDS if word in url.lower()]
    if keyword_hits:
        findings.append(f"Suspicious keywords found: {', '.join(keyword_hits)}")

    if re.search(r"%[0-9a-fA-F]{2}", url):
        findings.append("URL contains encoded characters")

    return {"findings": findings, "score": min(len(findings) * 10, 40)}
