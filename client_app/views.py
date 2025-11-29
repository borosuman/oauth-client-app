from __future__ import annotations

import json
import os
import secrets
from typing import Any, Dict
from urllib.parse import urlencode

import requests
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST
from dotenv import load_dotenv

load_dotenv()


def _get_required_env(var_name: str) -> str:
    value = os.environ.get(var_name)
    if not value:
        raise RuntimeError(f"{var_name} env var must be set")
    return value


CLIENT_ID = _get_required_env("OAUTH_CLIENT_ID")
CLIENT_SECRET = _get_required_env("OAUTH_CLIENT_SECRET")
SERVER_URL = os.environ.get("OAUTH_SERVER_URL", "http://127.0.0.1:8001").rstrip("/")
SCOPE = os.environ.get("OAUTH_SCOPE", "read")
REDIRECT_URI = os.environ.get("OAUTH_REDIRECT_URI", "http://localhost:9001/callback")

AUTHORIZE_URL = f"{SERVER_URL}/o/authorize/"
TOKEN_URL = f"{SERVER_URL}/o/token/"
ME_ENDPOINT = f"{SERVER_URL}/api/me/"
STATE_CACHE_PREFIX = "client_app.oauth_state."
STATE_CACHE_TTL = 300  # seconds


def home(request: HttpRequest) -> HttpResponse:
    token: Dict[str, Any] | None = request.session.get("token")
    api_response: Dict[str, Any] | None = request.session.get("api_response")
    context = {
        "server_url": SERVER_URL,
        "scope": SCOPE,
        "token": json.dumps(token, indent=2) if token else None,
        "api_response": json.dumps(api_response, indent=2) if api_response else None,
    }
    return render(request, "client_app/home.html", context)


def login(request: HttpRequest) -> HttpResponse:
    state = secrets.token_urlsafe(16)
    cache.set(f"{STATE_CACHE_PREFIX}{state}", True, STATE_CACHE_TTL)
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": state,
    }
    return redirect(f"{AUTHORIZE_URL}?{urlencode(params)}")


def callback(request: HttpRequest) -> HttpResponse:
    session_snapshot = {key: request.session.get(key) for key in request.session.keys()}
    print(f"[client_app] Session contents during callback: {session_snapshot}")

    state = request.GET.get("state")
    if not state:
        return HttpResponseBadRequest("Missing state parameter.")

    state_key = f"{STATE_CACHE_PREFIX}{state}"
    if not cache.get(state_key):
        return HttpResponseBadRequest("State mismatch, aborting.")
    cache.delete(state_key)

    code = request.GET.get("code")
    if not code:
        return HttpResponseBadRequest("Missing authorization code.")

    token_response = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=10,
    )

    if not token_response.ok:
        print(token_response.status_code, token_response.text)
        message = f"Token exchange failed: {token_response.text}"
        return HttpResponseBadRequest(message)

    token_json = token_response.json()
    request.session["token"] = token_json

    api_response = requests.get(
        ME_ENDPOINT,
        headers={"Authorization": f"Bearer {token_json['access_token']}"},
        timeout=10,
    )
    if api_response.ok:
        request.session["api_response"] = api_response.json()
    else:
        request.session["api_response"] = {
            "error": "API call failed",
            "details": api_response.text,
            "status_code": api_response.status_code,
        }

    return redirect("client_app:home")


@require_POST
def logout_view(request: HttpRequest) -> HttpResponse:
    """Clear session data when the user clicks the logout button."""
    request.session.flush()
    return redirect("client_app:home")
