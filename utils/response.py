"""
utils/response.py
Standardised JSON response helpers for Cybex Recon Engine APIs.
"""

from flask import jsonify


def success_response(data: dict, status_code: int = 200):
    """
    Wrap *data* in a standard success envelope and return a Flask Response.

    Parameters
    ----------
    data : dict
        The payload to return to the client.
    status_code : int, optional
        HTTP status code (default 200).

    Returns
    -------
    flask.Response
    """
    payload = {"ok": True, "data": data}
    return jsonify(payload), status_code


def error_response(message: str, status_code: int = 400):
    """
    Return a standard error envelope as a Flask Response.

    Parameters
    ----------
    message : str
        Human-readable error description.
    status_code : int, optional
        HTTP status code (default 400).

    Returns
    -------
    flask.Response
    """
    payload = {"ok": False, "error": message}
    return jsonify(payload), status_code
