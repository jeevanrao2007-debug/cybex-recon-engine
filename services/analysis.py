"""
services/analysis.py
Security Analysis Engine for Cybex Recon Engine – Module 3.

Analyses assessment results, computes a risk score, generates structured
findings with recommendations.

For live scan results: queries OSV.dev REST API for real CVE data keyed on
banner-extracted service names/versions.  Falls back to the local
_SECURITY_RULES dictionary when OSV returns no results or no version info
could be extracted from the banner.

No live network scanning is performed in this module.
"""

import concurrent.futures
import json
import time
from datetime import datetime, timezone

import requests

from config import OSV_API_URL, OSV_CACHE_TTL, OSV_REQUEST_TIMEOUT


# ---------------------------------------------------------------------------
# Local security rule definitions (fallback when OSV.dev has no match)
# ---------------------------------------------------------------------------
# Each rule maps a service name (upper-case) to a finding template.

_SECURITY_RULES: dict[str, dict] = {
    "TELNET": {
        "severity": "critical",
        "cve": "CVE-2020-10188",
        "description": (
            "Telnet transmits all data—including authentication credentials—as "
            "cleartext. Any network observer can capture usernames, passwords, "
            "and session content without decryption."
        ),
        "recommendation": (
            "Disable Telnet immediately. Replace with SSH (port 22) and enforce "
            "key-based authentication with PasswordAuthentication disabled in sshd_config."
        ),
        "reference": "https://www.cisa.gov/uscert/ncas/alerts/TA18-106A",
    },
    "FTP": {
        "severity": "high",
        "cve": "CVE-1999-0527",
        "description": (
            "FTP transmits credentials and file content in cleartext over port 21. "
            "Anonymous FTP access may expose sensitive data to unauthenticated users."
        ),
        "recommendation": (
            "Replace FTP with SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS). "
            "If FTP is required, disable anonymous access and enforce TLS encryption."
        ),
        "reference": "https://owasp.org/www-community/vulnerabilities/Cleartext_Transmission_of_Sensitive_Information",
    },
    "SMB": {
        "severity": "critical",
        "cve": "CVE-2017-0144",
        "description": (
            "SMBv1 (port 445) is vulnerable to EternalBlue, the exploit used by WannaCry "
            "and NotPetya. Exposure of this port on a public interface is a critical risk."
        ),
        "recommendation": (
            "Disable SMBv1 entirely and block port 445 at the firewall perimeter. "
            "If SMB is needed internally, enforce SMBv3 with encryption enabled."
        ),
        "reference": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
    },
    "RDP": {
        "severity": "critical",
        "cve": "CVE-2019-0708",
        "description": (
            "Remote Desktop Protocol (port 3389) is a frequent brute-force and "
            "exploit target. BlueKeep (CVE-2019-0708) allows unauthenticated remote "
            "code execution on unpatched systems."
        ),
        "recommendation": (
            "Restrict RDP to a VPN-only allowlist or dedicated jump host. "
            "Enable Network Level Authentication (NLA), enforce MFA, and apply "
            "all BlueKeep patches (MS19-0708)."
        ),
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708",
    },
    "REDIS": {
        "severity": "critical",
        "cve": "CVE-2022-0543",
        "description": (
            "Redis (port 6379) ships with no authentication by default. An exposed "
            "Redis instance allows unauthenticated read/write access, which can lead "
            "to data theft, arbitrary file writes, or remote code execution via Lua."
        ),
        "recommendation": (
            "Bind Redis to 127.0.0.1 only. Enable AUTH with a strong password "
            "and enable TLS. Disable the CONFIG, DEBUG, and SLAVEOF commands if "
            "not required."
        ),
        "reference": "https://redis.io/docs/manual/security/",
    },
    "MONGODB": {
        "severity": "critical",
        "cve": "CVE-2019-2389",
        "description": (
            "MongoDB (port 27017) historically defaults to no authentication, "
            "exposing all databases to any reachable client. Billions of records "
            "have been leaked due to this misconfiguration."
        ),
        "recommendation": (
            "Enable MongoDB access control (--auth). Bind to localhost or a "
            "private interface only. Use TLS for client connections and audit "
            "database access logs regularly."
        ),
        "reference": "https://www.mongodb.com/docs/manual/security/",
    },
    "RPC": {
        "severity": "high",
        "cve": "CVE-2003-0352",
        "description": (
            "Microsoft RPC (port 135) has a history of critical exploits including "
            "MS03-026, which led to widespread worm infections. It exposes internal "
            "service enumeration data."
        ),
        "recommendation": (
            "Block port 135 at the network perimeter. If RPC is required for "
            "Windows services, restrict it to internal VLANs only and apply all "
            "Microsoft security patches."
        ),
        "reference": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-026",
    },
    "NETBIOS": {
        "severity": "high",
        "cve": "CVE-2017-0143",
        "description": (
            "NetBIOS Session Service (port 139) exposes Windows host and workgroup "
            "information. It can be used to enumerate network shares and is "
            "associated with SMB-related exploits."
        ),
        "recommendation": (
            "Disable NetBIOS over TCP/IP in network adapter settings. "
            "Replace NetBIOS name resolution with DNS. Block ports 137–139 at "
            "the perimeter firewall."
        ),
        "reference": "https://attack.mitre.org/techniques/T1046/",
    },
    "MYSQL": {
        "severity": "high",
        "cve": "CVE-2016-6662",
        "description": (
            "MySQL (port 3306) exposed on a public interface allows direct database "
            "connection attempts. Weak credentials or SQL injection can result in full "
            "data compromise or remote code execution."
        ),
        "recommendation": (
            "Bind MySQL to 127.0.0.1 or a private network interface. "
            "Remove the anonymous user account and revoke all remote root logins. "
            "Use connection-level TLS for any necessary remote access."
        ),
        "reference": "https://dev.mysql.com/doc/refman/8.0/en/security.html",
    },
    "MSSQL": {
        "severity": "high",
        "cve": "CVE-2020-0618",
        "description": (
            "Microsoft SQL Server (port 1433) exposed publicly allows direct connection "
            "attempts. Weak passwords and SA account misconfiguration are common attack vectors."
        ),
        "recommendation": (
            "Bind MSSQL to private interfaces only. Disable the SA account or enforce "
            "a strong password. Enable SQL Server Audit and Windows Authentication mode."
        ),
        "reference": "https://docs.microsoft.com/en-us/sql/relational-databases/security/",
    },
    "POSTGRESQL": {
        "severity": "high",
        "cve": "CVE-2019-10164",
        "description": (
            "PostgreSQL (port 5432) exposed publicly allows direct connection attempts. "
            "Misconfigurations in pg_hba.conf can grant unauthenticated access to "
            "all databases."
        ),
        "recommendation": (
            "Restrict PostgreSQL to loopback or private subnets in pg_hba.conf. "
            "Use scram-sha-256 authentication, enable SSL, and run PostgreSQL "
            "as a non-root user."
        ),
        "reference": "https://www.postgresql.org/docs/current/auth-pg-hba-conf.html",
    },
    "VNC": {
        "severity": "high",
        "cve": "CVE-2019-15681",
        "description": (
            "VNC (port 5900) often ships with weak or absent authentication. "
            "Many implementations lack encryption, allowing session hijacking "
            "or screen capture by network observers."
        ),
        "recommendation": (
            "Disable VNC if not required. If VNC is needed, use a VPN tunnel "
            "or SSH port-forwarding to secure the connection. Enforce strong "
            "password authentication and update VNC software to patched versions."
        ),
        "reference": "https://www.cve.org/CVERecord?id=CVE-2019-15681",
    },
    "ELASTICSEARCH": {
        "severity": "high",
        "cve": "CVE-2015-1427",
        "description": (
            "Elasticsearch (port 9200) ships without authentication by default, "
            "exposing all indexed data to unauthenticated HTTP requests."
        ),
        "recommendation": (
            "Enable X-Pack security or OpenSearch security plugin. Bind to "
            "localhost or a private interface. Use TLS and role-based access control."
        ),
        "reference": "https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html",
    },
    "MEMCACHED": {
        "severity": "high",
        "cve": "CVE-2018-1000115",
        "description": (
            "Memcached (port 11211) has no authentication and has been abused in "
            "massive DDoS reflection/amplification attacks."
        ),
        "recommendation": (
            "Bind Memcached to 127.0.0.1 only. Block port 11211 at the perimeter. "
            "If UDP is not required, disable it with the -U 0 flag."
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2018-1000115",
    },
    "HTTP": {
        "severity": "medium",
        "cve": "CWE-319",
        "description": (
            "HTTP (port 80) transmits web content without encryption. Sensitive data "
            "such as session tokens, form inputs, and API responses are visible to "
            "network observers."
        ),
        "recommendation": (
            "Redirect all HTTP traffic to HTTPS (port 443) using a 301 permanent "
            "redirect. Enforce HSTS (Strict-Transport-Security) with a minimum "
            "max-age of 31536000 seconds."
        ),
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
    },
    "HTTP-ALT": {
        "severity": "medium",
        "cve": "CWE-319",
        "description": (
            "An alternate HTTP port (8080) exposes unencrypted web traffic. "
            "Development servers running on this port often lack production-grade "
            "hardening, potentially leaking internal application details."
        ),
        "recommendation": (
            "Move all web services to HTTPS. If port 8080 is a proxy, ensure "
            "it enforces TLS termination and does not reveal version headers "
            "or internal path information."
        ),
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
    },
    "JUPYTER": {
        "severity": "high",
        "cve": "CVE-2022-21699",
        "description": (
            "Jupyter Notebook / JupyterLab exposed publicly may allow unauthenticated "
            "arbitrary code execution on the host system."
        ),
        "recommendation": (
            "Never expose Jupyter publicly. Bind to localhost, require a strong "
            "token, and access through an SSH tunnel or a properly authenticated reverse proxy."
        ),
        "reference": "https://jupyter-notebook.readthedocs.io/en/stable/security.html",
    },
    "SMTP": {
        "severity": "medium",
        "cve": "CWE-306",
        "description": (
            "SMTP (port 25) without mandatory authentication can act as an open "
            "relay, allowing third parties to send spam or phishing email through "
            "the server."
        ),
        "recommendation": (
            "Require SMTP AUTH for all outbound mail. Configure SPF, DKIM, and "
            "DMARC DNS records to prevent spoofing. Enable STARTTLS and reject "
            "unauthenticated relay attempts."
        ),
        "reference": "https://www.rfc-editor.org/rfc/rfc5321",
    },
    "DNS": {
        "severity": "medium",
        "cve": "CVE-2020-1350",
        "description": (
            "DNS (port 53) misconfigurations can allow zone transfers to arbitrary "
            "clients, exposing the full network topology. DNS is also abused in "
            "amplification DDoS attacks."
        ),
        "recommendation": (
            "Restrict zone transfers (AXFR) to authorised secondary name servers only. "
            "Rate-limit recursive queries. Apply the SIGRed patch (CVE-2020-1350) "
            "on Windows DNS servers."
        ),
        "reference": "https://www.cisa.gov/uscert/ncas/alerts/aa20-195a",
    },
    "IMAP": {
        "severity": "low",
        "cve": "CWE-319",
        "description": (
            "IMAP on port 143 may allow unencrypted login if STARTTLS is not "
            "enforced. Credentials transmitted in cleartext can be intercepted "
            "on unsecured networks."
        ),
        "recommendation": (
            "Enforce STARTTLS on port 143 and disable plaintext login capability. "
            "Prefer IMAPS (port 993) for guaranteed TLS from connection start. "
            "Disable SSLv3 and TLS 1.0/1.1 in the mail server configuration."
        ),
        "reference": "https://www.rfc-editor.org/rfc/rfc3501",
    },
    "POP3": {
        "severity": "medium",
        "cve": "CWE-319",
        "description": (
            "POP3 on port 110 transmits email and credentials in cleartext unless "
            "STARTTLS is negotiated. This exposes mailbox content to passive eavesdropping."
        ),
        "recommendation": (
            "Disable POP3 on port 110 and migrate users to POP3S (port 995). "
            "If port 110 must remain, mandate STARTTLS before any AUTH command "
            "is accepted."
        ),
        "reference": "https://www.rfc-editor.org/rfc/rfc1939",
    },
    "SSH": {
        "severity": "medium",
        "cve": "CVE-2023-38408",
        "description": (
            "SSH (port 22) is a common target for automated brute-force credential "
            "attacks. Weak passwords or outdated SSH daemon versions can lead to "
            "unauthorised server access."
        ),
        "recommendation": (
            "Disable password authentication and enforce SSH key pairs. "
            "Move SSH to a non-standard port if possible. Use fail2ban or similar "
            "tools to block repeated failed attempts. Keep OpenSSH updated."
        ),
        "reference": "https://www.openssh.com/security.html",
    },
    "HTTPS": {
        "severity": "low",
        "cve": "CWE-326",
        "description": (
            "HTTPS (port 443) relies on TLS. Misconfigured TLS settings such as "
            "weak cipher suites, expired certificates, or SSLv3/TLS 1.0 support "
            "can undermine encryption."
        ),
        "recommendation": (
            "Enforce TLS 1.2 minimum (TLS 1.3 preferred). Disable RC4, 3DES, and "
            "CBC-mode ciphers. Implement HSTS and verify certificates are from a "
            "trusted CA with a minimum 2048-bit RSA or 256-bit ECDSA key."
        ),
        "reference": "https://ssl-config.mozilla.org/",
    },
    "SMTPS": {
        "severity": "low",
        "cve": "CWE-326",
        "description": (
            "SMTPS (port 465) uses implicit TLS. Misconfigured or outdated TLS "
            "settings can weaken the security of mail submission."
        ),
        "recommendation": (
            "Verify TLS 1.2+ is enforced and no weak cipher suites are accepted. "
            "Regularly audit the mail server TLS configuration using tools such "
            "as testssl.sh or Qualys SSL Labs."
        ),
        "reference": "https://www.rfc-editor.org/rfc/rfc8314",
    },
    "SMTP-SUBMIT": {
        "severity": "low",
        "cve": "CWE-306",
        "description": (
            "Mail submission on port 587 should enforce SASL authentication and "
            "STARTTLS. Without these controls, third parties may relay email "
            "or intercept credentials."
        ),
        "recommendation": (
            "Require STARTTLS before AUTH on port 587. Enforce SASL and reject "
            "unauthenticated relay. Configure rate limiting to mitigate spam abuse."
        ),
        "reference": "https://www.rfc-editor.org/rfc/rfc6409",
    },
}

# ---------------------------------------------------------------------------
# Risk scoring weights
# ---------------------------------------------------------------------------
_RISK_WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1}
_SCORE_CAP    = 100


# ---------------------------------------------------------------------------
# OSV.dev lookup with TTL in-memory cache
# ---------------------------------------------------------------------------

# Cache structure: { cache_key: (timestamp_float, osv_result_dict | None) }
_OSV_CACHE: dict[str, tuple[float, dict | None]] = {}


def _extract_version_from_banner(banner: str) -> str | None:
    """
    Attempt to extract a version string from a service banner.

    Examples handled:
      "SSH-2.0-OpenSSH_8.9.0 Ubuntu-3ubuntu0.1"  → "8.9.0"
      "220 mail.example.com ESMTP Postfix 3.6.4"  → "3.6.4"
      "220-ProFTPD 1.3.7a Server"                  → "1.3.7a"
    """
    import re
    # Common version patterns: digits with dots and optional trailing letter
    match = re.search(r"\b(\d+\.\d+[\d.a-zA-Z]*)\b", banner)
    return match.group(1) if match else None


def _osv_query(service_name: str, version: str | None) -> dict | None:
    """
    Query OSV.dev for vulnerabilities related to *service_name* (and optional
    *version*).  Returns the first matching OSV record, or None.

    Results are cached in _OSV_CACHE for OSV_CACHE_TTL seconds to avoid
    hammering the API during repeated assessments.
    """
    # If no version was extracted from banner, skip slow OSV network queries
    # and rely on the rich curated security rules.
    if not version:
        return None

    # Normalise to common package names OSV recognises
    _OSV_PACKAGE_MAP = {
        "SSH":           "openssh",
        "OPENSSH":       "openssh",
        "FTP":           "proftpd",
        "HTTP":          "apache2",
        "HTTPS":         "apache2",
        "HTTP-ALT":      "apache2",
        "HTTPS-ALT":     "apache2",
        "MYSQL":         "mysql-server",
        "POSTGRESQL":    "postgresql",
        "REDIS":         "redis",
        "MONGODB":       "mongodb",
        "ELASTICSEARCH": "elasticsearch",
        "SMTP":          "postfix",
        "TELNET":        "telnetd",
        "MEMCACHED":     "memcached",
        "MSSQL":         "mssql-server",
    }
    pkg_name = _OSV_PACKAGE_MAP.get(service_name.upper(), service_name.lower())
    cache_key = f"{pkg_name}:{version}"

    # Check TTL cache
    if cache_key in _OSV_CACHE:
        cached_at, cached_result = _OSV_CACHE[cache_key]
        if time.time() - cached_at < float(OSV_CACHE_TTL):
            return cached_result

    payload: dict = {
        "package": {"name": pkg_name, "ecosystem": "OSS-Fuzz"},
        "version": version,
    }

    try:
        resp = requests.post(
            OSV_API_URL,
            json=payload,
            timeout=float(OSV_REQUEST_TIMEOUT),
        )
        if resp.status_code == 200:
            data  = resp.json()
            vulns = data.get("vulns", [])
            result = vulns[0] if vulns else None
        else:
            result = None
    except Exception:  # noqa: BLE001 – network errors should not crash the report
        result = None

    _OSV_CACHE[cache_key] = (time.time(), result)
    return result


def _osv_to_finding_fields(osv_record: dict, service_name: str, port: int) -> dict | None:
    """
    Convert an OSV.dev vulnerability record into a finding dict.

    Returns None if the record doesn't contain enough data to be useful.
    """
    vuln_id = osv_record.get("id", "N/A")
    summary = osv_record.get("summary", "")
    details = osv_record.get("details", "")
    refs    = osv_record.get("references", [])

    description = details or summary or f"Known vulnerability in {service_name}."
    reference   = refs[0]["url"] if refs else f"https://osv.dev/vulnerability/{vuln_id}"

    # Severity from database_specific or affected severity, fallback to 'high'
    severity = "high"
    for affected in osv_record.get("affected", []):
        db_spec = affected.get("database_specific", {})
        sev     = db_spec.get("severity", "").lower()
        if sev in ("critical", "high", "medium", "low"):
            severity = sev
            break

    return {
        "service":        service_name,
        "port":           port,
        "severity":       severity,
        "cve":            vuln_id,
        "description":    description[:600],   # cap length for UI
        "recommendation": (
            f"Review the OSV advisory {vuln_id} and apply the recommended patches "
            f"for {service_name}. See: {reference}"
        ),
        "reference":      reference,
        "source":         "osv.dev",
    }


# ---------------------------------------------------------------------------
# Core analysis helpers (unchanged logic, new OSV data source)
# ---------------------------------------------------------------------------

def _match_rule(service_name: str, banner: str = "", port: int = 0) -> dict | None:
    """
    Look up a security rule for *service_name*.

    Strategy:
    1. If banner contains a version string, query OSV.dev.
    2. If OSV returns a usable record, synthesise a finding from it.
    3. Otherwise fall back to the local _SECURITY_RULES dict.
    """
    svc_upper = service_name.upper().strip()

    version = _extract_version_from_banner(banner) if banner else None
    osv_record = _osv_query(svc_upper, version) if version else None

    if osv_record:
        finding = _osv_to_finding_fields(osv_record, service_name, port)
        if finding:
            return {
                "severity":       finding["severity"],
                "cve":            finding["cve"],
                "description":    finding["description"],
                "recommendation": finding["recommendation"],
                "reference":      finding["reference"],
                "source":         "osv.dev",
            }

    # Local fallback
    local = _SECURITY_RULES.get(svc_upper)
    if local:
        return {**local, "source": "local"}

    return None


def _compute_risk_score(findings: list[dict]) -> int:
    """Compute a 0–100 integer risk score based on analysed findings."""
    score = 0
    for finding in findings:
        sev = str(finding.get("severity") or "low").lower().strip()
        if sev not in _RISK_WEIGHTS:
            sev = "low"
        score += _RISK_WEIGHTS.get(sev, 1)
    return min(score, _SCORE_CAP)


def _risk_label(score: int) -> str:
    """Convert a numeric risk score to a human-readable band."""
    if score >= 70:
        return "Critical"
    if score >= 45:
        return "High"
    if score >= 20:
        return "Medium"
    return "Low"


def _evaluate_single_service(svc: dict) -> dict:
    """Evaluate a single open service into a finding dictionary."""
    banner   = svc.get("banner", "")
    svc_name = svc.get("service_name") or svc.get("service") or f"Port-{svc.get('port')}"
    port     = svc.get("port", 0)
    src_type = svc.get("service_source", "port_mapping")

    rule = _match_rule(svc_name, banner, port)

    if rule is None:
        raw_risk = str(svc.get("risk_level") or "low").lower().strip()
        fallback_sev = raw_risk if raw_risk in ("critical", "high", "medium", "low") else "low"
        rule = {
            "severity":       fallback_sev,
            "cve":            "N/A",
            "description":    svc.get("educational_note", "No description available."),
            "recommendation": (
                "Review this service exposure and ensure hardening guidelines are enforced."
            ),
            "reference":  "https://attack.mitre.org/techniques/T1046/",
            "source":     "rule_based_recommendation",
        }

    finding_sev = str(rule.get("severity") or "low").lower().strip()
    if finding_sev not in ("critical", "high", "medium", "low"):
        finding_sev = "low"

    return {
        "service":        svc_name,
        "port":           port,
        "severity":       finding_sev,
        "cve":            rule.get("cve", "N/A"),
        "description":    rule.get("description", "No description available."),
        "recommendation": rule.get("recommendation", "Review service exposure."),
        "reference":      rule.get("reference", "https://attack.mitre.org/techniques/T1046/"),
        "banner":         banner if banner else "Not observed",
        "service_source": src_type,
        "data_source":    rule.get("source", "rule_based_recommendation"),
        "finding_type":   "OSV CVE Match" if rule.get("source") == "osv.dev" else "Rule-based security recommendation",
    }


def _build_findings(services: list[dict]) -> list[dict]:
    """
    Match each open service against OSV.dev (then local rules) concurrently
    and produce structured findings, sorted by severity (critical → low).
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    open_services = [s for s in services if s.get("status") == "open"]
    if not open_services:
        return []

    max_workers = min(10, len(open_services))
    findings = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_svc = {
            executor.submit(_evaluate_single_service, svc): svc
            for svc in open_services
        }
        for future in concurrent.futures.as_completed(future_to_svc):
            try:
                finding = future.result()
                findings.append(finding)
            except Exception as exc:  # noqa: BLE001
                svc = future_to_svc[future]
                svc_name = svc.get("service_name") or svc.get("service") or f"Port-{svc.get('port')}"
                findings.append({
                    "service":        svc_name,
                    "port":           svc.get("port", 0),
                    "severity":       "low",
                    "cve":            "N/A",
                    "description":    f"Analysis error: {exc}",
                    "recommendation": "Review port exposure manually.",
                    "reference":      "https://attack.mitre.org/techniques/T1046/",
                    "banner":         "Not observed",
                    "service_source": "unknown",
                    "data_source":    "error_fallback",
                    "finding_type":   "Error fallback",
                })

    findings.sort(key=lambda f: (severity_order.get(f["severity"], 99), f["port"]))
    return findings


def _count_by_severity(findings: list[dict]) -> dict[str, int]:
    """Count findings grouped by severity label."""
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        level = f.get("severity", "low")
        if level in counts:
            counts[level] += 1
    return counts


def _compute_score_breakdown(services: list[dict]) -> dict[str, int]:
    """Count open services grouped by their defined risk level."""
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for svc in services:
        if svc.get("status") != "open":
            continue
        level = svc.get("risk_level", "low")
        if level in breakdown:
            breakdown[level] += 1
    return breakdown


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyse(assessment_data: dict) -> dict:
    """
    Analyse an assessment result and return a full Module 3 report payload.

    Parameters
    ----------
    assessment_data : dict
        The dict returned by ``run_assessment()``.

    Returns
    -------
    dict
        Analysis report including risk score, findings, OSV data source info,
        live_scan flag, and auth_confirmed_at timestamp.
    """
    services   = assessment_data.get("services", [])
    target     = assessment_data.get("target", "Unknown")
    scenario   = assessment_data.get("scenario", "Unknown")
    live_scan  = assessment_data.get("live_scan", False)
    auth_ts    = assessment_data.get("auth_confirmed_at")

    findings      = _build_findings(services)
    risk_score    = _compute_risk_score(findings)
    risk_lbl      = _risk_label(risk_score)
    sev_counts    = _count_by_severity(findings)
    score_bd      = sev_counts
    open_services = sum(1 for s in services if s.get("status") == "open")

    scan_type_label = "real local machine TCP connect scan" if live_scan else "simulated test scan"
    osv_count       = sum(1 for f in findings if f.get("data_source") == "osv.dev")

    exec_summary = (
        f"The real local machine service assessment of target '{target}' ({scenario}) "
        f"assessed {len(services)} configured TCP ports and identified {open_services} open service(s). "
        f"Security analysis yielded {len(findings)} open service exposure finding(s) across "
        f"{sev_counts['critical']} critical, {sev_counts['high']} high, "
        f"{sev_counts['medium']} medium, and {sev_counts['low']} low risk categories. "
        f"The calculated risk score is {risk_score}/100 ({risk_lbl}). "
        f"Data source: {scan_type_label}. "
        f"{osv_count} finding(s) enriched with OSV.dev CVE data. "
        f"All non-CVE security recommendations are rule-based hardening guidance."
    )

    return {
        "target":            target,
        "scenario":          scenario,
        "assessment_date":   assessment_data.get("timestamp", ""),
        "analysis_date":     datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "services_total":    len(services),
        "open_services":     open_services,
        "risk_score":        risk_score,
        "risk_label":        risk_lbl,
        "score_breakdown":   score_bd,
        "severity_counts":   sev_counts,
        "findings":          findings,
        "executive_summary": exec_summary,
        "live_scan":         live_scan,
        "auth_confirmed_at": auth_ts,
    }
