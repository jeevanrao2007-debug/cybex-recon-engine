"""
config.py
Centralised configuration settings for Cybex Recon Engine.
"""

import os

# ---------------------------------------------------------------------------
# DNS resolver settings
# ---------------------------------------------------------------------------
DNS_TIMEOUT             = 3.0
DNS_RESOLVER_SERVERS    = ["8.8.8.8", "8.8.4.4"]

# Timeout (seconds) for RDAP lookups via ipwhois
RDAP_TIMEOUT            = 6.0

# ---------------------------------------------------------------------------
# Flask Application settings
# ---------------------------------------------------------------------------
DEFAULT_PORT            = int(os.environ.get("PORT", 5000))

# Rate limiting / debouncing settings
RATE_LIMIT_COOLDOWN     = 2.0   # Cooldown window in seconds

# ---------------------------------------------------------------------------
# Authorization gate
# ---------------------------------------------------------------------------
# Hard-coded allowlist for live TCP scanning.
# Only these hostnames / IPs will be accepted by the live scanner.
# Anything outside this set is redirected to the fixture-based educational
# fallback and clearly labelled as simulated.
#
# scanme.nmap.org is Nmap's public opt-in test host — explicitly authorised
# for security research scans by its owner (https://nmap.org/book/legal-issues.html).
# 127.0.0.1 / localhost refers to the user's own machine.
ALLOWED_TARGETS: frozenset = frozenset({
    "scanme.nmap.org",
    "127.0.0.1",
    "localhost",
})

# ---------------------------------------------------------------------------
# Live port scanner settings
# ---------------------------------------------------------------------------
# Top ~30 common ports to probe in the live TCP connect scan.
SCAN_PORTS: list[int] = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    111,   # RPCBind
    135,   # Microsoft RPC
    139,   # NetBIOS Session
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    465,   # SMTPS
    587,   # SMTP Submission
    993,   # IMAPS
    995,   # POP3S
    1433,  # MSSQL
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8080,  # HTTP-Alt
    8443,  # HTTPS-Alt
    27017, # MongoDB
    8888,  # Jupyter / misc
    9200,  # Elasticsearch
    9300,  # Elasticsearch transport
    11211, # Memcached
]

# TCP connect timeout per port attempt (seconds)
SCAN_TIMEOUT: float         = 1.5

# Banner read timeout after a successful connect (seconds)
BANNER_TIMEOUT: float       = 2.0

# Max bytes to read as banner per open port
BANNER_READ_BYTES: int      = 256

# Max simultaneous in-flight TCP connection attempts
SCAN_CONCURRENCY: int       = 20

# ---------------------------------------------------------------------------
# OSV.dev API settings (Module 3)
# ---------------------------------------------------------------------------
OSV_API_URL             = "https://api.osv.dev/v1/query"
OSV_REQUEST_TIMEOUT     = 2.0     # seconds per OSV HTTP request (fast-fail)
OSV_CACHE_TTL           = 3600    # seconds (1 hour) for in-memory cache
