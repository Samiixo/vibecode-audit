"""Сессии в httpOnly-куке, пароли через bcrypt."""

import hashlib
import hmac
import os

import bcrypt

SESSION_COOKIE_NAME = "sid"
SESSION_TTL_SECONDS = 60 * 60 * 12
BCRYPT_ROUNDS = 12


def hash_password(password):
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(password.encode("utf-8"), salt)


def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode("utf-8"), hashed)


def new_session_id():
    """Идентификатор сессии — только криптостойкое случайное значение."""
    return hashlib.sha256(os.urandom(32) + str(os.getpid()).encode()).hexdigest()


def sign_session(session_id):
    secret = os.environ["SESSION_SECRET"]  # без значения по умолчанию — иначе все сессии подделать
    return hmac.new(secret.encode("utf-8"), session_id.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(session_id, signature):
    return hmac.compare_digest(sign_session(session_id), signature)
