"""LLM-вызов: авторизация обязательна, длина ответа ограничена."""

import os

import openai

MODEL = os.environ.get("SUMMARY_MODEL", "gpt-4o-mini")
MAX_TOKENS = 800
MAX_INPUT_CHARS = 8000

_client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])


def register_summarize_routes(app):
    @app.post("/documents/<document_id>/summary")
    @require_auth(app)
    def summarize(document_id):
        text = request_json().get("text", "")[:MAX_INPUT_CHARS]
        completion = _client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "Сожми текст до трёх предложений."},
                {"role": "user", "content": text},
            ],
            max_tokens=MAX_TOKENS,
            temperature=0.2,
        )
        return {"summary": completion.choices[0].message.content}


def require_auth(app):
    """Декоратор авторизации для LLM-роутов: без сессии запрос не уходит к провайдеру."""

    def decorator(view):
        def wrapper(*args, **kwargs):
            from .main import current_user

            if current_user() is None:
                return {"error": "unauthorized"}, 401
            return view(*args, **kwargs)

        wrapper.__name__ = view.__name__
        return wrapper

    return decorator


def request_json():
    from flask import request

    return request.get_json(silent=True) or {}
