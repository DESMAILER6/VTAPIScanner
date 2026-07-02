import base64
import os
import requests

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def get_url_report(url: str) -> dict:
    if not VT_API_KEY:
        return {"enabled": False, "error": "VT_API_KEY is not configured"}

    headers = {"x-apikey": VT_API_KEY}
    url_id = vt_url_id(url)
    endpoint = f"{VT_BASE_URL}/urls/{url_id}"

    try:
        response = requests.get(endpoint, headers=headers, timeout=20)

        if response.status_code == 404:
            return {
                "enabled": True,
                "found": False,
                "message": "URL was not found in VirusTotal. Submit it manually or add submission support later.",
            }

        response.raise_for_status()
        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "enabled": True,
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "reputation": attributes.get("reputation"),
            "final_url": attributes.get("last_final_url"),
            "tags": attributes.get("tags", []),
        }
    except requests.exceptions.RequestException as exc:
        return {"enabled": True, "error": str(exc)}
