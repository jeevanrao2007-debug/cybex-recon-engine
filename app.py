"""
app.py
Cybex Recon Engine – Module 1, Module 2 & Module 3
Flask application entry point.
Exposes the homepage route, /resolve (M1), /assessment and /scenarios (M2),
/analyse and /report/download (M3).
"""

import os
from flask import Flask, render_template, request, Response
from services.validators import validate_target, classify_input, get_local_ipv4_addresses, is_local_target
from services.dns_lookup import lookup_domain, lookup_ipv4
from services.assessment import run_assessment, list_scenarios
from services.analysis import analyse
from services.report_builder import generate_txt_report, generate_json_report
from utils.response import success_response, error_response
from utils.rate_limiter import limit_assessment_rate
from utils.logger import log_assessment
from config import DEFAULT_PORT, ALLOWED_TARGETS

# ---------------------------------------------------------------------------
# App initialisation
# ---------------------------------------------------------------------------

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    """Lightweight health check endpoint for cloud monitoring & Render checks."""
    return {"status": "healthy", "service": "cybex-recon-engine"}, 200


@app.route("/")
def landing():
    """Render the cinematic landing page."""
    return render_template("landing.html")


@app.route("/dashboard")
def dashboard():
    """Render the main reconnaissance and analysis dashboard."""
    return render_template("index.html")


@app.route("/resolve", methods=["POST"])
def resolve():
    """
    POST /resolve

    Accepts a JSON body ``{ "target": "<domain or IPv4>" }``.
    Validates the input strictly, resolves domains to IPv4, fetches all DNS
    record types (A, AAAA, MX, NS, TXT, CNAME, SOA) and RDAP ownership info,
    then returns a standardised JSON response.

    Returns
    -------
    flask.Response
        JSON with ``ok`` bool, and either ``data`` or ``error`` key.
    """
    body = request.get_json(silent=True)

    if not body or "target" not in body:
        return error_response("Request body must contain a 'target' field.", 400)

    raw_target = body["target"].strip()

    is_valid, err_msg = validate_target(raw_target, allow_scenario=False)
    if not is_valid:
        return error_response(err_msg, 422)

    kind = classify_input(raw_target)

    try:
        if kind == "domain":
            result = lookup_domain(raw_target)
        else:  # kind == "ipv4"
            result = lookup_ipv4(raw_target)
    except Exception as exc:  # noqa: BLE001
        return error_response(f"Target unresolvable: {exc}", 400)

    if result.get("status") == "failed":
        return error_response(
            result.get("error") or f"Target unresolvable: could not resolve '{raw_target}'.", 400
        )

    return success_response(result)


# ---------------------------------------------------------------------------
# Module 2 Routes
# ---------------------------------------------------------------------------

@app.route("/local-targets", methods=["GET"])
def local_targets():
    """
    GET /local-targets

    Dynamically discover IPv4 addresses assigned to the local host machine running Flask.
    """
    try:
        targets = get_local_ipv4_addresses()
        return success_response({
            "success": True,
            "targets": targets,
        })
    except Exception as exc:  # noqa: BLE001
        return error_response(f"Failed to discover local targets: {exc}", 500)


@app.route("/scenarios", methods=["GET"])
def scenarios():
    """
    GET /scenarios

    Returns the list of available local targets and scenarios for UI dropdown population.
    """
    try:
        targets = get_local_ipv4_addresses()
        scenario_list = list_scenarios()
        return success_response({
            "success":          True,
            "scenarios":        scenario_list,
            "targets":          targets,
            "allowed_targets":  [t["ip"] for t in targets],
        })
    except RuntimeError as exc:
        return error_response(str(exc), 500)


@app.route("/assessment", methods=["POST"])
@limit_assessment_rate
def assessment():
    """
    POST /assessment

    Accepts a JSON body:
        {
          "target": "<local_ipv4_or_localhost>",
          "authorized": true,
          "auth_confirmed_at": "<ISO-8601 UTC timestamp or null>"
        }

    Performs a real local machine TCP service assessment against an address
    assigned to this computer. Rejects remote or unauthorized target IPs.
    """
    body = request.get_json(silent=True)

    if not body or "target" not in body:
        return error_response("Request body must contain a 'target' field.", 400)

    raw_target        = body["target"].strip()
    authorized        = bool(body.get("authorized", True))
    auth_confirmed_at = body.get("auth_confirmed_at") or None

    # Strict local machine target validation
    if not is_local_target(raw_target):
        log_assessment(target=raw_target, outcome="unauthorized_remote_target", extra={"error": "Not a local target"})
        return error_response("Only addresses assigned to this local machine can be assessed.", 400)

    try:
        result = run_assessment(
            raw_target,
            authorized=True,
            auth_confirmed_at=auth_confirmed_at,
        )
        log_assessment(
            target=raw_target,
            outcome="success",
            extra={
                "scenario":       result.get("scenario"),
                "live_scan":      True,
                "total_services": result.get("summary", {}).get("total", 0),
                "open_services":  result.get("summary", {}).get("open", 0),
                "authorized":     True,
            },
        )
    except ValueError as exc:
        log_assessment(target=raw_target, outcome="validation_error", extra={"error": str(exc)})
        return error_response(str(exc), 400)
    except RuntimeError as exc:
        log_assessment(target=raw_target, outcome="failed", extra={"error": str(exc)})
        return error_response(str(exc), 500)
    except Exception as exc:  # noqa: BLE001
        log_assessment(target=raw_target, outcome="error", extra={"error": str(exc)})
        return error_response(f"Unexpected error during assessment: {exc}", 500)

    return success_response(result)


# ---------------------------------------------------------------------------
# Module 3 Routes
# ---------------------------------------------------------------------------

@app.route("/analyse", methods=["POST"])
def analyse_report():
    """
    POST /analyse

    Accepts a JSON body ``{ "assessment": <assessment-data-dict> }``.
    Passes the assessment payload through the analysis engine (including
    OSV.dev lookup for live scan results) and returns a structured security
    report with risk score, findings, and recommendations.

    Returns
    -------
    flask.Response
        JSON with ``ok`` bool and either ``data`` or ``error`` key.
    """
    body = request.get_json(silent=True)

    assessment_data = body.get("assessment") or body
    if not isinstance(assessment_data, dict) or ("services" not in assessment_data and "results" not in assessment_data):
        return error_response("Request body must contain an 'assessment' object or assessment data containing 'services'.", 400)

    try:
        result = analyse(assessment_data)
    except Exception as exc:  # noqa: BLE001
        return error_response(f"Analysis error: {exc}", 500)

    return success_response(result)


@app.route("/report/download", methods=["POST"])
def download_report():
    """
    POST /report/download

    Accepts a JSON body::

        {
          "assessment": <assessment-data-dict>,
          "format":     "txt" | "json"
        }

    Runs the analysis engine and returns the report as a downloadable file
    attachment. Supported formats are ``'txt'`` and ``'json'``.

    Returns
    -------
    flask.Response
        File download response (text/plain or application/json).
    """
    body = request.get_json(silent=True)

    analysis_data   = body.get("analysis")
    assessment_data = body.get("assessment")
    fmt = body.get("format", "txt").lower().strip()

    if fmt not in ("txt", "json"):
        return error_response("'format' must be 'txt' or 'json'.", 400)

    if not analysis_data and not assessment_data:
        return error_response("Request body must contain an 'analysis' or 'assessment' field.", 400)

    try:
        if isinstance(analysis_data, dict) and "findings" in analysis_data:
            analysis = analysis_data
        else:
            analysis = analyse(assessment_data)
    except Exception as exc:  # noqa: BLE001
        return error_response(f"Analysis error: {exc}", 500)

    target_slug = (
        analysis["target"].replace(".", "-").replace("/", "-")[:30]
    )
    date_slug = analysis["analysis_date"][:10]

    if fmt == "json":
        content  = generate_json_report(analysis)
        mime     = "application/json"
        filename = f"cre_report_{target_slug}_{date_slug}.json"
    else:
        content  = generate_txt_report(analysis)
        mime     = "text/plain"
        filename = f"cre_report_{target_slug}_{date_slug}.txt"

    return Response(
        content,
        mimetype=mime,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type":        f"{mime}; charset=utf-8",
        },
    )


# ---------------------------------------------------------------------------
# Dev server entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")
    app.run(debug=debug_mode, host="0.0.0.0", port=DEFAULT_PORT)
