# Cybex Recon Engine

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-green.svg)](https://flask.palletsprojects.com/)
[![Render](https://img.shields.io/badge/Deploy%20to-Render-46E3B7.svg)](https://render.com/)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

An advanced, dark-themed cybersecurity reconnaissance and intelligence engine built with **Python Flask**, **Gunicorn**, **Bootstrap 5**, and **Vanilla JavaScript**. Features high-performance DNS resolution, authorized service vulnerability assessments, real-time threat intelligence lookup via OSV.dev, and structured forensic report generation.

---

## ⚡ Key Modules & Capabilities

### 1. 🌐 Cinematic Landing & Reconnaissance Dashboard
* **Cinematic Landing Page (`/`)**: Hero visual presentation with real-time system metrics, feature breakdown, and quick launch triggers.
* **Cybersecurity Operations Center (`/dashboard`)**: Full-featured interactive terminal-inspired dashboard with live status cards, DNS records tables, and threat scoring.

### 2. 🔍 Module 1 – DNS Intelligence & Target Resolution
* Resolves domain targets to IPv4 addresses via `dnspython`.
* Passive DNS enumeration: **A, AAAA, MX, NS, TXT, CNAME, and SOA** records.
* Autonomous **RDAP / Whois ownership lookup** powered by `ipwhois` (Autonomous System Number, Org name, CIDR, Country).
* Server-side strict RFC validation and sanitization.

### 3. 🛡️ Module 2 – Local Service Security Assessment
* Concurrent multi-threaded TCP connect scanner targeting local interfaces and loopback (`127.0.0.1`).
* Dynamic host network interface discovery (`/local-targets`).
* Automated banner grabbing (non-intrusive) with service classification.
* Built-in rate limiting and anti-abuse safeguards.

### 4. 🧠 Module 3 – Automated Threat Analysis & Reporting
* Risk scoring algorithm evaluating open attack surface and exposure levels.
* Real-time CVE / Vulnerability correlation querying the **OSV.dev REST API**.
* Actionable remediation and hardening recommendations.
* **Instant Export**: Download forensic audit reports as formatted plain text (`.txt`) or structured JSON (`.json`).

---

## 📁 Repository Structure

```
cybex-recon-engine/
├── app.py                   # Main Flask application entrypoint & API routes
├── config.py                # Centralized environment and scanner settings
├── gunicorn.conf.py         # Production WSGI server configuration
├── Procfile                 # Process file for cloud container deployment
├── render.yaml              # Render Blueprint deployment definition
├── requirements.txt         # Pinned Python package dependencies
├── .python-version          # Python runtime pin (3.11.10)
├── .gitignore               # Clean git exclusions
├── run.bat                  # One-click Windows launch script
├── data/
│   └── fixtures.json        # Pre-configured test scenarios & mock services
├── services/
│   ├── __init__.py
│   ├── analysis.py          # Threat scoring & OSV.dev CVE correlation
│   ├── assessment.py        # Concurrent TCP port assessment & banner collection
│   ├── dns_lookup.py        # DNS record queries & RDAP ownership lookups
│   ├── report_builder.py    # Text and JSON forensic report exporters
│   └── validators.py        # Input validation & local interface discovery
├── utils/
│   ├── __init__.py
│   ├── logger.py            # Structured 12-factor JSON application logging
│   ├── rate_limiter.py      # IP and request rate limiters
│   └── response.py          # Unified JSON API response helpers
├── templates/
│   ├── index.html           # Main Cyber Recon Dashboard
│   └── landing.html         # Cinematic Landing page
└── static/
    ├── css/style.css        # Dashboard styling
    ├── js/app.js            # Dashboard asynchronous client logic
    ├── images/              # Assets & icons
    └── landing/             # Landing page CSS, JS, and media assets
```

---

## 🚀 Local Development Setup

### Prerequisites
* Python 3.10+ (Python 3.11 recommended)
* Git

### Quick Start (Windows)
Double-click `run.bat` or run:
```cmd
run.bat
```

### Manual Setup (Linux / macOS / Windows)

```bash
# 1. Clone repository
git clone https://github.com/jeevanrao2007-debug/cybex-recon-engine.git
cd cybex-recon-engine

# 2. Create and activate a virtual environment
python -m venv .venv

# On Linux / macOS:
source .venv/bin/activate
# On Windows (cmd / powershell):
.venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start local development server
python app.py
```

The application will be live at **http://localhost:5000** (Landing) and **http://localhost:5000/dashboard** (Dashboard).

---

## ☁️ Deploying on Render

You can deploy Cybex Recon Engine on **Render** (Free Web Service) in just a few minutes using either method below.

### Method A: One-Click Blueprint (Recommended)

1. Log into your account at [Render.com](https://render.com/).
2. In the top navigation, click **New +** and select **Blueprint**.
3. Connect your GitHub account and select the repository: `cybex-recon-engine`.
4. Render will automatically read `render.yaml` from the root of the repository and populate all service configurations:
   * **Name**: `cybex-recon-engine`
   * **Environment**: `Python`
   * **Build Command**: `pip install -r requirements.txt`
   * **Start Command**: `gunicorn --config gunicorn.conf.py app:app`
   * **Health Check Path**: `/health`
5. Click **Apply**. Render will automatically build and deploy your live site!

---

### Method B: Manual Web Service Setup

If you prefer configuring it manually via the Render Dashboard:

1. Go to [Render Dashboard](https://dashboard.render.com/) and click **New +** → **Web Service**.
2. Choose **Build and deploy from a Git repository**.
3. Select your repository: `https://github.com/jeevanrao2007-debug/cybex-recon-engine`.
4. Fill in the following settings:
   * **Name**: `cybex-recon-engine` (or any name you like)
   * **Region**: Choose the closest region (e.g., Singapore, Frankfurt, Oregon, Ohio)
   * **Branch**: `main`
   * **Root Directory**: *(leave blank)*
   * **Runtime**: `Python 3`
   * **Build Command**:
     ```bash
     pip install -r requirements.txt
     ```
   * **Start Command**:
     ```bash
     gunicorn --config gunicorn.conf.py app:app
     ```
   * **Instance Type**: `Free`
5. Expand **Advanced**:
   * **Health Check Path**: `/health`
   * Add Environment Variable:
     * `PYTHON_VERSION` = `3.11.10`
     * `FLASK_DEBUG` = `0`
6. Click **Create Web Service**.
7. Wait 1–2 minutes for the build to finish. Render will provide you with a free `https://<your-service-name>.onrender.com` URL!

---

## 🔌 API Reference

### 1. `GET /health`
Returns health check status for load balancers and deployment monitoring.
* **Response**: `{"status": "healthy", "service": "cybex-recon-engine"}` (200 OK)

### 2. `POST /resolve`
DNS reconnaissance endpoint.
* **Request**: `{"target": "example.com"}`
* **Response**:
```json
{
  "ok": true,
  "data": {
    "target": "example.com",
    "resolved_ip": "93.184.216.34",
    "a_records": ["93.184.216.34"],
    "mx_records": [{"preference": 0, "exchange": "."}],
    "status": "success",
    "rdap": { ... }
  }
}
```

### 3. `GET /local-targets`
Discovers available network interfaces and addresses on the host machine.

### 4. `POST /assessment`
Performs authorized local service checks against an assigned IP or loopback address.

### 5. `POST /analyse`
Takes assessment data and evaluates vulnerabilities, returning risk score, CVSS severity, CVE matches, and remediation notes.

### 6. `POST /report/download`
Generates downloadable audit reports.
* **Request**: `{"assessment": { ... }, "format": "txt" | "json"}`
* **Response**: File download stream (`.txt` or `.json`).

---

## 🛡️ Security & Ethical Disclaimer

This tool is strictly designed for **educational, testing, and authorized defensive security assessments**. Active port probing is restricted by default to local machine addresses and opt-in test fixtures. Always ensure you have explicit written authorization before scanning any target network.
