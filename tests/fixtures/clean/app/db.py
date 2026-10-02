"""Доступ к данным: только параметризованные запросы и проверка владельца записи."""

import os

import psycopg
from psycopg.rows import dict_row

POOL = None


def init_pool(dsn):
    global POOL
    if not dsn:
        raise RuntimeError("DATABASE_URL не задан: приложение обязано падать, а не работать вслепую")
    POOL = psycopg.ConnectionPool(dsn, min_size=1, max_size=8, row_factory=dict_row)


def find_document(current_user, document_id):
    """Фильтр идёт по id И по владельцу — чужой документ не отдаём даже при верном id."""
    with POOL.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, title, body FROM documents WHERE id = %s AND user_id = %s",
                (document_id, current_user["id"]),
            )
            return cur.fetchone()


def create_document(current_user, title, body):
    with POOL.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO documents (user_id, title, body) VALUES (%s, %s, %s) RETURNING id",
                (current_user["id"], title, body),
            )
            return cur.fetchone()["id"]
