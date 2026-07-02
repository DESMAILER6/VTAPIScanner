def calculate_score(vt: dict, blocklists: dict, heuristics: dict) -> dict:
    score = 0
    reasons = []

    if vt.get("enabled") and vt.get("found"):
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        score += malicious * 20
        score += suspicious * 10

        if malicious:
            reasons.append(f"VirusTotal malicious detections: {malicious}")
        if suspicious:
            reasons.append(f"VirusTotal suspicious detections: {suspicious}")
    elif vt.get("error"):
        reasons.append(f"VirusTotal unavailable: {vt.get('error')}")

    for name in ["spamhaus_dbl", "surbl"]:
        result = blocklists.get(name, {})
        if result.get("listed"):
            score += 40
            reasons.append(f"Listed on {name}")

    score += heuristics.get("score", 0)
    reasons.extend(heuristics.get("findings", []))
    score = min(score, 100)

    if score >= 70:
        verdict = "High risk"
    elif score >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Low risk"

    return {"score": score, "verdict": verdict, "reasons": reasons}
