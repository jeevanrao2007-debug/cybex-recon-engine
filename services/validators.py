"""
services/validators.py
Input validation utilities for Cybex Recon Engine – Module 1 & 2.
Validates IPv4 addresses, domain names, and performs dynamic local interface discovery.
"""

import re
import socket

# Regex pattern for a valid IPv4 address
_IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Regex pattern for a valid domain name (RFC-compliant)
_DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

# Regex pattern for a loose IP structure to catch malformed IPs (e.g. 999.1.1.1)
_LOOSE_IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def is_valid_ipv4(value: str) -> bool:
    """Return True if *value* is a valid IPv4 address."""
    return bool(_IPV4_PATTERN.match(value.strip()))


def is_valid_domain(value: str) -> bool:
    """Return True if *value* looks like a valid domain name."""
    return bool(_DOMAIN_PATTERN.match(value.strip().lower()))


def classify_input(value: str) -> str:
    """
    Classify *value* as ``'ipv4'``, ``'domain'``, or ``'invalid'``.
    """
    stripped = value.strip()
    if is_valid_ipv4(stripped):
        return "ipv4"
    if is_valid_domain(stripped):
        return "domain"
    return "invalid"


def get_local_ipv4_addresses() -> list[dict]:
    """
    Dynamically discover IPv4 addresses assigned to the machine running Flask.

    Returns
    -------
    list[dict]
        List of dicts: ``{"label": str, "ip": str, "type": "loopback"|"local_interface"}``
    """
    discovered: list[dict] = []
    seen_ips: set[str] = set()

    # 1. Always include loopback 127.0.0.1
    discovered.append({
        "label": "Localhost (Loopback)",
        "ip": "127.0.0.1",
        "type": "loopback"
    })
    seen_ips.add("127.0.0.1")

    # 2. Discover local interface IPs via hostname resolution
    try:
        hostname = socket.gethostname()
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        for ip in ip_list:
            if is_valid_ipv4(ip) and ip not in seen_ips and not ip.startswith("169.254."):
                label = f"This PC - Local Network ({ip})"
                discovered.append({
                    "label": label,
                    "ip": ip,
                    "type": "local_interface"
                })
                seen_ips.add(ip)
    except Exception:
        pass

    # 3. Discover primary egress interface IP via UDP socket probe
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            if is_valid_ipv4(primary_ip) and primary_ip not in seen_ips and not primary_ip.startswith("169.254."):
                discovered.append({
                    "label": f"This PC - Primary Interface ({primary_ip})",
                    "ip": primary_ip,
                    "type": "local_interface"
                })
                seen_ips.add(primary_ip)
    except Exception:
        pass

    return discovered


def is_local_target(target: str) -> bool:
    """
    Return True iff *target* is a valid local address assigned to this computer.
    """
    stripped = target.strip().lower()
    if stripped in ("localhost", "127.0.0.1"):
        return True

    local_targets = get_local_ipv4_addresses()
    local_ips = {t["ip"] for t in local_targets}

    if stripped in local_ips:
        return True

    # Resolve target string to IPv4 and check against local IPs
    try:
        resolved_ip = socket.gethostbyname(stripped)
        if resolved_ip in local_ips or resolved_ip == "127.0.0.1":
            return True
    except Exception:
        pass

    return False


def validate_target(target: str, allow_scenario: bool = False) -> tuple[bool, str]:
    """
    Strictly validate a target input (domain or IP).
    """
    stripped = target.strip()
    if not stripped:
        return False, "Target input cannot be empty."

    # Reject URLs with schemes
    if "://" in stripped or stripped.lower().startswith(("http:", "https:", "ftp:")):
        return False, "Input contains a URL scheme (e.g., 'http://'). Please enter a raw domain or IPv4 address only."

    # Reject URLs with paths or query parameters
    if "/" in stripped or "\\" in stripped:
        return False, "Input contains a URL path or directory separator ('/'). Please enter a raw domain or IPv4 address only."
    if "?" in stripped or "#" in stripped:
        return False, "Input contains URL parameters or fragments. Please enter a raw domain or IPv4 address only."

    # Check for invalid characters
    if not re.match(r"^[a-zA-Z0-9.\-]+$", stripped):
        return False, "Target contains invalid characters. Only alphanumeric characters, dots (.), and hyphens (-) are allowed."

    # Classify input
    kind = classify_input(stripped)

    if kind == "invalid":
        if _LOOSE_IP_PATTERN.match(stripped):
            return False, f"'{stripped}' is a malformed IPv4 address. Each octet must be between 0 and 255."
        return False, f"'{stripped}' is not a valid domain name or IPv4 address structure."

    return True, ""
