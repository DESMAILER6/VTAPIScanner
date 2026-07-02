import dns.resolver
import tldextract


def extract_registered_domain(url: str) -> str:
    parsed = tldextract.extract(url)
    if not parsed.domain or not parsed.suffix:
        return ""
    return f"{parsed.domain}.{parsed.suffix}"


def dnsbl_lookup(domain: str, zone: str) -> dict:
    query = f"{domain}.{zone}"

    try:
        answers = dns.resolver.resolve(query, "A")
        return {"listed": True, "zone": zone, "responses": [str(a) for a in answers]}
    except dns.resolver.NXDOMAIN:
        return {"listed": False, "zone": zone}
    except dns.resolver.NoAnswer:
        return {"listed": False, "zone": zone}
    except dns.resolver.Timeout:
        return {"listed": False, "zone": zone, "error": "DNS lookup timed out"}
    except Exception as exc:
        return {"listed": False, "zone": zone, "error": str(exc)}


def check_blocklists(url: str) -> dict:
    domain = extract_registered_domain(url)

    if not domain:
        return {"domain": None, "error": "Could not extract registered domain"}

    return {
        "domain": domain,
        "spamhaus_dbl": dnsbl_lookup(domain, "dbl.spamhaus.org"),
        "surbl": dnsbl_lookup(domain, "multi.surbl.org"),
    }
