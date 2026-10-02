"""Пользователи хранят только хеш пароля, роли живут в БД, а не в запросе."""

import psycopg

from .db import POOL
from .session import hash_password


def create_user(email, password, plan="free"):
    with POOL.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (email, password_hash, plan) VALUES (%s, %s, %s) RETURNING id",
                (email, hash_password(password), plan),
            )
            return cur.fetchone()["id"]


def get_user_by_email(email):
    if not email:
        return None
    with POOL.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, email, password_hash, plan FROM users WHERE email = %s",
                (email,),
            )
            return cur.fetchone()
