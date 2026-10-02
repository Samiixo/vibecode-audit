"""HTTP-слой: авторизация на каждом маршруте, CORS по списку, лимит на вход."""

import os

from flask import Flask, jsonify, request
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .db import create_document, find_document, init_pool
from .session import SESSION_COOKIE_NAME, new_session_id, sign_session, verify_password
from .store import get_user_by_email

ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["200/minute"])
app.config["SESSION_COOKIE_NAME"] = SESSION_COOKIE_NAME
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = 1024 * 512
init_pool(os.environ.get("DATABASE_URL"))


@app.errorhandler(RateLimitExceeded)
def on_rate_limit(_exc):
    return jsonify({"error": "too many requests"}), 429


def current_user():
    """Аутентификация по подписанной сессии. Роли из тела запроса не берём никогда."""
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    signature = request.headers.get("X-Session-Signature", "")
    if not sid or not verify_signature(sid, signature):
        return None
    return {"id": sid, "authenticated": True}


def require_user(view):
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return jsonify({"error": "unauthorized"}), 401
        return view(user, *args, **kwargs)

    wrapper.__name__ = view.__name__
    return wrapper


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin and origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


@app.post("/login")
@limiter.limit("5/minute")
def login():
    data = request.get_json() or {}
    user = get_user_by_email(data.get("email", ""))
    if user is None or not verify_password(data.get("password", ""), user["password_hash"]):
        return jsonify({"error": "invalid credentials"}), 401
    sid = new_session_id()
    response = jsonify({"ok": True})
    response.set_cookie(SESSION_COOKIE_NAME, sid, httponly=True, secure=True, samesite="Lax")
    response.headers["X-Session-Signature"] = sign_session(sid)
    return response


@app.get("/documents/<document_id>")
@require_user
def get_document(document_id):
    row = find_document(current_user(), document_id)
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(row)


@app.post("/documents")
@require_user
def add_document():
    data = request.get_json() or {}
    doc_id = create_document(current_user(), data.get("title", ""), data.get("body", ""))
    return jsonify({"id": doc_id}), 201


from .summarize import register_summarize_routes  # noqa: E402  (роут требует app)

register_summarize_routes(app)
