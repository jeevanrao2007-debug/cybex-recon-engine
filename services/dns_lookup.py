"""
services/dns_lookup.py
DNS resolution utilities for Cybex Recon Engine – Module 1.

Resolves domains to IPv4 and retrieves A / MX / NS / TXT / CNAME / SOA /
AAAA records via dnspython.  Also performs passive RDAP ownership lookups
for resolved IP addresses using ipwhois.
"""

import socket

import dns.resolver
import dns.exception

try:
    from ipwhois import IPWhois
    from ipwhois.exceptions import IPDefinedError
    _IPWHOIS_AVAILABLE = True
except ImportError:
    _IPWHOIS_AVAILABLE = False

from config import DNS_TIMEOUT, DNS_RESOLVER_SERVERS, RDAP_TIMEOUT


# ---------------------------------------------------------------------------
# Shared resolver factory
# ---------------------------------------------------------------------------

def get_resolver() -> dns.resolver.Resolver:
    """
    Build and return a dns.resolver.Resolver instance configured with
    centralised timeouts and nameservers.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout  = float(DNS_TIMEOUT)
    resolver.lifetime = float(DNS_TIMEOUT)
    if DNS_RESOLVER_SERVERS:
        resolver.nameservers = DNS_RESOLVER_SERVERS
    return resolver


# ---------------------------------------------------------------------------
# IPv4 resolution helpers
# ---------------------------------------------------------------------------

def resolve_ipv4(domain: str) -> str:
    """
    Resolve *domain* to its primary IPv4 address.

    Falls back to the OS resolver (socket) on server timeouts or unreachable
    nameservers.

    Raises
    ------
    ValueError
        If the domain cannot be resolved to an IPv4 address.
    """
    resolver = get_resolver()
    try:
        answers = resolver.resolve(domain.strip(), "A")
        if answers:
            return answers[0].address
        raise ValueError("Target unresolvable: No A records returned.")
    except dns.resolver.NXDOMAIN as exc:
        raise ValueError(
            "Target unresolvable: The domain name does not exist (NXDOMAIN)."
        ) from exc
    except dns.exception.Timeout as exc:
        try:
            return socket.gethostbyname(domain.strip())
        except socket.gaierror:
            raise ValueError("Target unresolvable: DNS resolution timed out.") from exc
    except dns.resolver.NoNameservers as exc:
        try:
            return socket.gethostbyname(domain.strip())
        except socket.gaierror:
            raise ValueError(
                "Target unresolvable: No DNS nameservers responded."
            ) from exc
    except dns.resolver.NoAnswer as exc:
        raise ValueError(
            "Target unresolvable: No A records found for the domain."
        ) from exc
    except dns.exception.DNSException as exc:
        raise ValueError(
            f"Target unresolvable: DNS resolution failure: {exc}"
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise ValueError(
            f"Target unresolvable: Unexpected error during DNS resolution: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Individual record-type getters (all return empty on failure – not an error)
# ---------------------------------------------------------------------------

def get_a_records(domain: str) -> list[str]:
    """Return a list of IPv4 addresses from the A records of *domain*."""
    try:
        resolver = get_resolver()
        answers  = resolver.resolve(domain.strip(), "A")
        return [rdata.address for rdata in answers]
    except (dns.exception.DNSException, Exception):
        return []


def get_aaaa_records(domain: str) -> list[str]:
    """Return a list of IPv6 addresses from the AAAA records of *domain*."""
    try:
        resolver = get_resolver()
        answers  = resolver.resolve(domain.strip(), "AAAA")
        return [rdata.address for rdata in answers]
    except (dns.exception.DNSException, Exception):
        return []


def get_mx_records(domain: str) -> list[dict]:
    """
    Return a list of MX record dicts sorted by preference (ascending).

    Each dict: ``{ preference: int, exchange: str }``
    """
    try:
        resolver = get_resolver()
        answers  = resolver.resolve(domain.strip(), "MX")
        records  = [
            {
                "preference": int(rdata.preference),
                "exchange":   str(rdata.exchange).rstrip("."),
            }
            for rdata in answers
        ]
        return sorted(records, key=lambda r: r["preference"])
    except (dns.exception.DNSException, Exception):
        return []


def get_ns_records(domain: str) -> list[str]:
    """Return a list of NS (nameserver) hostname strings for *domain*."""
    try:
        resolver = get_resolver()
        answers  = resolver.resolve(domain.strip(), "NS")
        return sorted(str(rdata.target).rstrip(".") for rdata in answers)
    except (dns.exception.DNSException, Exception):
        return []


def get_txt_records(domain: str) -> list[str]:
    """Return a list of TXT record strings for *domain*."""
    try:
        resolver = get_resolver()
        answers  = resolver.resolve(domain.strip(), "TXT")
        results  = []
        for rdata in answers:
            # Each TXT record can contain multiple strings; join them.
            joined = " ".join(
                part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
                for part in rdata.strings
            )
            results.append(joined)
        return results
    except (dns.exception.DNSException, Exception):
        return []


def get_cname_record(domain: str) -> str | None:
    """
    Return the CNAME target for *domain*, or ``None`` if no CNAME exists.

    Note: most authoritative domains do NOT have a CNAME at the apex; this
    is expected and not treated as an error.
    """
    try:
        resolver = get_resolver()
        answers  = resolver.resolve(domain.strip(), "CNAME")
        if answers:
            return str(answers[0].target).rstrip(".")
        return None
    except (dns.exception.DNSException, Exception):
        return None


def get_soa_record(domain: str) -> dict | None:
    """
    Return the SOA record for *domain* as a dict, or ``None`` if unavailable.

    Dict keys: ``mname``, ``rname``, ``serial``, ``refresh``, ``retry``,
    ``expire``, ``minimum``.
    """
    try:
        resolver = get_resolver()
        answers  = resolver.resolve(domain.strip(), "SOA")
        if answers:
            soa = answers[0]
            return {
                "mname":   str(soa.mname).rstrip("."),
                "rname":   str(soa.rname).rstrip(".").replace("\\.", "@", 1),
                "serial":  int(soa.serial),
                "refresh": int(soa.refresh),
                "retry":   int(soa.retry),
                "expire":  int(soa.expire),
                "minimum": int(soa.minimum),
            }
        return None
    except (dns.exception.DNSException, Exception):
        return None


# ---------------------------------------------------------------------------
# RDAP / IP ownership lookup
# ---------------------------------------------------------------------------

def get_rdap_info(ip: str) -> dict | None:
    """
    Perform a passive RDAP lookup for *ip* using ipwhois.

    Returns a dict with ownership metadata, or ``None`` on failure.
    This is a read-only, non-intrusive query to public RDAP registries.

    Returns
    -------
    dict | None
        Keys: ``asn``, ``asn_description``, ``network_cidr``,
        ``network_name``, ``country``, ``registrar``.
    """
    if not _IPWHOIS_AVAILABLE:
        return None

    # RFC 1918 / loopback addresses don't have RDAP records
    _SKIP_PREFIXES = ("127.", "10.", "192.168.", "::1")
    if any(ip.startswith(pfx) for pfx in _SKIP_PREFIXES) or ip == "localhost":
        return {"note": "Private/loopback address — no RDAP record available."}

    # 172.16.0.0/12 range
    try:
        parts = ip.split(".")
        if len(parts) == 4 and parts[0] == "172" and 16 <= int(parts[1]) <= 31:
            return {"note": "Private address range — no RDAP record available."}
    except (ValueError, IndexError):
        pass

    try:
        obj    = IPWhois(ip, timeout=int(RDAP_TIMEOUT))
        result = obj.lookup_rdap(depth=1)
        network = result.get("network") or {}
        return {
            "asn":             result.get("asn", "N/A"),
            "asn_description": result.get("asn_description", "N/A"),
            "network_cidr":    network.get("cidr", "N/A"),
            "network_name":    network.get("name", "N/A"),
            "country":         network.get("country", "N/A"),
            "registrar":       result.get("asn_registry", "N/A"),
        }
    except IPDefinedError:
        return {"note": "Reserved/private IP — no RDAP record."}
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Public composite lookup functions
# ---------------------------------------------------------------------------

def lookup_domain(domain: str) -> dict:
    """
    Perform a full DNS footprint for *domain*.

    Returns a dict with keys:
      - ``target``      – original domain
      - ``resolved_ip`` – primary A record IP (str | None)
      - ``a_records``   – all A record IPs (list[str])
      - ``aaaa_records``– all AAAA record IPs (list[str])
      - ``mx_records``  – MX records (list[dict])
      - ``ns_records``  – NS hostnames (list[str])
      - ``txt_records`` – TXT strings (list[str])
      - ``cname``       – CNAME target (str | None)
      - ``soa``         – SOA dict (dict | None)
      - ``rdap``        – RDAP ownership info (dict | None)
      - ``status``      – 'success' | 'failed'
      - ``error``       – human-readable error (str | None)
    """
    result: dict = {
        "target":       domain,
        "resolved_ip":  None,
        "a_records":    [],
        "aaaa_records": [],
        "mx_records":   [],
        "ns_records":   [],
        "txt_records":  [],
        "cname":        None,
        "soa":          None,
        "rdap":         None,
        "status":       "success",
        "error":        None,
    }

    # Primary resolution (must succeed for status=success)
    try:
        result["resolved_ip"] = resolve_ipv4(domain)
    except ValueError as exc:
        result["status"] = "failed"
        result["error"]  = str(exc)
        return result

    # All record types — failures are silently empty, not fatal
    result["a_records"]    = get_a_records(domain)
    result["aaaa_records"] = get_aaaa_records(domain)
    result["mx_records"]   = get_mx_records(domain)
    result["ns_records"]   = get_ns_records(domain)
    result["txt_records"]  = get_txt_records(domain)
    result["cname"]        = get_cname_record(domain)
    result["soa"]          = get_soa_record(domain)

    # RDAP uses the primary resolved IP
    if result["resolved_ip"]:
        result["rdap"] = get_rdap_info(result["resolved_ip"])

    if result["resolved_ip"] is None and not result["a_records"]:
        result["status"] = "failed"
        result["error"]  = "Target unresolvable: No active records could be found."

    return result


def lookup_ipv4(ip: str) -> dict:
    """
    Build a result dict for a raw IPv4 address target with RDAP lookup.

    No active TCP scanning is performed here.
    """
    return {
        "target":       ip,
        "resolved_ip":  ip,
        "a_records":    [ip],
        "aaaa_records": [],
        "mx_records":   [],
        "ns_records":   [],
        "txt_records":  [],
        "cname":        None,
        "soa":          None,
        "rdap":         get_rdap_info(ip),
        "status":       "success",
        "error":        None,
    }
