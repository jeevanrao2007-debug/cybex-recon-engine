"""
services/assessment.py
Real Local Machine Service Assessment Layer for Cybex Recon Engine – Module 2.

Performs real concurrent TCP connect checks against addresses assigned to the
local host machine using Python's native socket library and ThreadPoolExecutor.

DISCLAIMER: Performs authorized TCP service checks on local network interfaces only.
"""

import concurrent.futures
import json
import os
import socket
import time
from datetime import datetime, timezone

from config import (
    BANNER_READ_BYTES,
    BANNER_TIMEOUT,
    SCAN_CONCURRENCY,
    SCAN_PORTS,
    SCAN_TIMEOUT,
)
from services.validators import get_local_ipv4_addresses, is_local_target

# Port -> Service Name mapping
_PORT_SERVICE: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    111:   "RPCBind",
    135:   "RPC",
    139:   "NetBIOS",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    587:   "SMTP-Submit",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    3306:  "MySQL",
    3389:  "RDP",
    5000:  "Flask Dev Server",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "Jupyter",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch Transport",
    11211: "Memcached",
    27017: "MongoDB",
}

# Service Name -> Exposure Risk Rating (for OPEN ports)
_SERVICE_RISK: dict[str, str] = {
    "FTP":                    "high",
    "SSH":                    "medium",
    "Telnet":                 "high",
    "SMTP":                   "medium",
    "DNS":                    "medium",
    "HTTP":                   "medium",
    "POP3":                   "medium",
    "RPCBind":                "high",
    "RPC":                    "high",
    "NetBIOS":                "high",
    "IMAP":                   "low",
    "HTTPS":                  "low",
    "SMB":                    "high",
    "SMTPS":                  "low",
    "SMTP-Submit":            "low",
    "IMAPS":                  "low",
    "POP3S":                  "low",
    "MSSQL":                  "high",
    "MySQL":                  "high",
    "RDP":                    "high",
    "Flask Dev Server":       "low",
    "PostgreSQL":             "high",
    "VNC":                    "high",
    "Redis":                  "high",
    "HTTP-Alt":               "medium",
    "HTTPS-Alt":              "low",
    "Jupyter":                "high",
    "Elasticsearch":          "high",
    "Elasticsearch Transport":"high",
    "Memcached":              "high",
    "MongoDB":                "high",
}

# Rule-based educational context notes
_EDUCATIONAL_NOTES: dict[str, str] = {
    "FTP":                    "File Transfer Protocol transmits credentials in cleartext. Prefer SFTP or FTPS.",
    "SSH":                    "Secure Shell provides encrypted administration. Enforce key-based auth and disable password logins.",
    "Telnet":                 "Telnet sends credentials in plaintext. Replace with SSH immediately.",
    "SMTP":                   "Simple Mail Transfer Protocol. Verify SASL auth, SPF, DKIM, and DMARC are configured.",
    "DNS":                    "Domain Name System. Restrict recursive queries and disable unauthorized zone transfers.",
    "HTTP":                   "Hypertext Transfer Protocol. Redirect plaintext HTTP traffic to HTTPS (port 443).",
    "POP3":                   "POP3 port 110 uses cleartext auth. Enforce POP3S (port 995) with TLS.",
    "RPCBind":                "RPCBind maps RPC services. Restrict access to internal networks.",
    "RPC":                    "Microsoft RPC. Restrict to internal networks and perimeter firewalls.",
    "NetBIOS":                "NetBIOS Session Service exposes Windows naming data. Disable externally.",
    "IMAP":                   "IMAP port 143. Enforce STARTTLS or use IMAPS (port 993).",
    "HTTPS":                  "HTTPS provides encrypted web communication. Verify valid TLS 1.2+ configuration.",
    "SMB":                    "Server Message Block (port 445). Restrict to private networks; block at perimeter.",
    "SMTPS":                  "SMTP over SSL/TLS for secure mail client submission.",
    "SMTP-Submit":            "Mail submission port 587. Require STARTTLS and SASL authentication.",
    "IMAPS":                  "IMAP over TLS. Preferred encrypted mail synchronization.",
    "POP3S":                  "POP3 over TLS for encrypted email retrieval.",
    "MSSQL":                  "Microsoft SQL Server. Bind to private interfaces and enforce strong authentication.",
    "MySQL":                  "MySQL Database. Bind to loopback (127.0.0.1) or private network interfaces only.",
    "RDP":                    "Remote Desktop Protocol. Protect behind a VPN or specific network allowlist.",
    "Flask Dev Server":       "Flask Development Server (port 5000). Use WSGI servers (Gunicorn/uWSGI) in production.",
    "PostgreSQL":             "PostgreSQL Database. Restrict listening interfaces in pg_hba.conf.",
    "VNC":                    "Virtual Network Computing. Use SSH tunneling or VPN for remote desktop access.",
    "Redis":                  "Redis Data Store. Require strong AUTH and bind to loopback (127.0.0.1).",
    "HTTP-Alt":               "Alternate HTTP port. Verify development headers or internal paths are not leaked.",
    "HTTPS-Alt":              "Alternate HTTPS port. Ensure TLS configuration matches primary HTTPS endpoints.",
    "Jupyter":                "Jupyter Notebook. Protect with token authentication and restrict access.",
    "Elasticsearch":          "Elasticsearch API. Restrict interface exposure and enable role-based access control.",
    "Elasticsearch Transport":"Elasticsearch node transport. Keep restricted to internal cluster nodes.",
    "Memcached":              "Memcached Caching System. Bind to loopback and block public UDP/TCP access.",
    "MongoDB":                "MongoDB Document Store. Enforce authentication and bind to 127.0.0.1.",
}


def list_scenarios() -> list[dict]:
    """
    Return a list of available local targets for UI dropdown population.
    Matches requirement for GET /local-targets.
    """
    targets = get_local_ipv4_addresses()
    return [
        {"id": t["ip"], "label": t["label"], "type": t["type"], "ip": t["ip"]}
        for t in targets
    ]


def _check_port(ip: str, port: int) -> dict:
    """
    Check a single TCP port on *ip* using native socket.connect_ex().
    Performs safe, non-fabricated banner grabbing if port is open.
    """
    service_name = _PORT_SERVICE.get(port, f"Unknown ({port})")
    
    # Determine default service source
    if port == 5000:
        service_source = "inferred"
    elif port in _PORT_SERVICE:
        service_source = "port_mapping"
    else:
        service_source = "unknown"

    edu_note = _EDUCATIONAL_NOTES.get(
        service_name,
        "Review this service for potential network exposure and hardening requirements."
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(float(SCAN_TIMEOUT))

    try:
        res = sock.connect_ex((ip, port))
        if res == 0:
            # Port is OPEN
            status = "open"
            evidence = "TCP connection accepted"
            banner = "Not observed"

            # Attempt safe banner collection
            try:
                sock.settimeout(float(BANNER_TIMEOUT))
                data = sock.recv(int(BANNER_READ_BYTES))
                if data:
                    raw = data.decode("utf-8", errors="replace").strip()
                    # Filter out non-printable binary characters
                    cleaned = "".join(ch for ch in raw if ch.isprintable() or ch in ("\r", "\n", "\t"))
                    if cleaned:
                        banner = cleaned[:120]
                        service_source = "observed_banner"
            except Exception:
                pass

            risk_level = _SERVICE_RISK.get(service_name, "medium")

            return {
                "port":             port,
                "protocol":         "TCP",
                "status":           "open",
                "service":          service_name,
                "service_name":     service_name,  # for compatibility
                "service_source":   service_source,
                "banner":           banner,
                "evidence":         evidence,
                "risk_level":       risk_level,
                "educational_note": edu_note,
            }

        else:
            # Port is CLOSED
            return {
                "port":             port,
                "protocol":         "TCP",
                "status":           "closed",
                "service":          service_name,
                "service_name":     service_name,
                "service_source":   service_source,
                "banner":           "Not applicable",
                "evidence":         "TCP connection refused or timed out",
                "risk_level":       "none",
                "educational_note": edu_note,
            }

    except Exception as exc:
        return {
            "port":             port,
            "protocol":         "TCP",
            "status":           "closed",
            "service":          service_name,
            "service_name":     service_name,
            "service_source":   service_source,
            "banner":           "Not applicable",
            "evidence":         f"Error: {exc}",
            "risk_level":       "none",
            "educational_note": edu_note,
        }
    finally:
        try:
            sock.close()
        except Exception:
            pass


def run_assessment(
    target: str,
    authorized: bool = True,
    auth_confirmed_at: str | None = None,
) -> dict:
    """
    Perform a real local machine TCP service assessment against *target*.

    Strictly validates that *target* is a local address assigned to this computer.
    Rejects external/arbitrary targets.
    """
    stripped_target = target.strip()

    # Reject non-local targets
    if not is_local_target(stripped_target):
        raise ValueError("Only addresses assigned to this local machine can be assessed.")

    # Resolve target to IPv4 address for socket connection
    try:
        target_ip = socket.gethostbyname(stripped_target)
    except socket.gaierror:
        target_ip = "127.0.0.1"

    start_time = time.time()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Perform concurrent TCP port checks using ThreadPoolExecutor
    max_workers = min(int(SCAN_CONCURRENCY), len(SCAN_PORTS))
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(_check_port, target_ip, port): port
            for port in SCAN_PORTS
        }
        for future in concurrent.futures.as_completed(future_to_port):
            try:
                res = future.result()
                results.append(res)
            except Exception as exc:
                port = future_to_port[future]
                results.append({
                    "port":             port,
                    "protocol":         "TCP",
                    "status":           "closed",
                    "service":          _PORT_SERVICE.get(port, f"Unknown ({port})"),
                    "service_name":     _PORT_SERVICE.get(port, f"Unknown ({port})"),
                    "service_source":   "unknown",
                    "banner":           "Not applicable",
                    "evidence":         f"Scan error: {exc}",
                    "risk_level":       "none",
                    "educational_note": "Port check failed.",
                })

    # Sort results by port number
    results.sort(key=lambda r: r["port"])
    duration = time.time() - start_time

    # Calculate dynamic summary metrics
    open_count = sum(1 for r in results if r["status"] == "open")
    closed_count = sum(1 for r in results if r["status"] == "closed")
    high_risk_count = sum(
        1 for r in results
        if r["status"] == "open" and r["risk_level"] in ("high", "critical")
    )

    summary = {
        "total":          len(results),
        "total_ports":    len(results),
        "open":           open_count,
        "open_ports":     open_count,
        "closed":         closed_count,
        "closed_ports":   closed_count,
        "high_risk":      high_risk_count,
    }

    return {
        "success":           True,
        "target":            stripped_target,
        "target_ip":         target_ip,
        "assessment_type":   "local_machine_tcp_assessment",
        "scenario":          f"Local Machine TCP Assessment ({stripped_target})",
        "timestamp":         timestamp,
        "duration_seconds":  round(duration, 2),
        "summary":           summary,
        "services":          results,
        "results":           results,
        "live_scan":         True,
        "auth_confirmed_at": auth_confirmed_at,
    }
