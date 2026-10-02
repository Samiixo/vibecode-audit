#!/usr/bin/env python3
"""checks_secrets.py — секреты в файлах, в git и в клиентских бандлах."""

import os
import re
import subprocess

import audit as core

# git с отключёнными хуками/fsmonitor: .git/config чужого репо не должен ничего исполнять
GIT_SAFE = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull]

# Порядок важен: более специфичные паттерны идут ПЕРЕД общими,
# дедуп по (файл, строка) оставляет первое совпадение — то есть самое специфичное.
# Все регулярки линейные (нет вложенных квантификаторов), чтобы не виснуть на минифицированных бандлах.
SECRET_PATTERNS = [
    ("secrets.private_key", "critical", "Приватный ключ (PEM)",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("secrets.stripe_live", "critical", "Stripe live key",
     re.compile(r"\bsk_live_[A-Za-z0-9]{16,}")),
    ("secrets.anthropic_key", "critical", "Anthropic API key",
     re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("secrets.openai_project", "critical", "OpenAI project key",
     re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}")),
    ("secrets.openrouter", "critical", "OpenRouter API key",
     re.compile(r"\bsk-or-v1-[A-Za-z0-9]{20,}")),
    ("secrets.openai_key", "critical", "OpenAI API key",
     re.compile(r"\bsk-(?!ant-|proj-|or-v1)[A-Za-z0-9_-]{20,}")),
    ("secrets.groq", "critical", "Groq API key",
     re.compile(r"\bgsk_[A-Za-z0-9]{32,}")),
    ("secrets.github_pat", "critical", "GitHub fine-grained token",
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}")),
    ("secrets.github_token", "critical", "GitHub token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("secrets.gitlab_pat", "critical", "GitLab personal access token",
     re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("secrets.google_api", "critical", "Google API key",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("secrets.slack_webhook", "critical", "Slack incoming webhook",
     re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}")),
    ("secrets.slack_token", "critical", "Slack token",
     re.compile(r"\bxox[baprse]-[A-Za-z0-9-]{10,}")),
    ("secrets.discord_bot", "critical", "Discord bot token",
     re.compile(r"\b[MNO][A-Za-z0-9_-]{23,26}\.[A-Za-z0-9_-]{6,8}\.[A-Za-z0-9_-]{27,30}")),
    ("secrets.discord_webhook", "critical", "Discord webhook",
     re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{20,}")),
    ("secrets.sendgrid", "critical", "SendGrid API key",
     re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}")),
    ("secrets.twilio", "critical", "Twilio API key",
     re.compile(r"\bSK[0-9a-fA-F]{32}")),
    ("secrets.npm_token", "critical", "npm access token",
     re.compile(r"\bnpm_[A-Za-z0-9]{30,}")),
    ("secrets.pypi_token", "critical", "PyPI token",
     re.compile(r"\bpypi-[A-Za-z0-9_-]{16,}")),
    ("secrets.huggingface", "critical", "HuggingFace token",
     re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("secrets.replicate", "critical", "Replicate API token",
     re.compile(r"\br8_[A-Za-z0-9]{30,}")),
    ("secrets.supabase_secret", "critical", "Supabase secret key",
     re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}")),
    ("secrets.supabase_service", "critical", "Supabase service_role JWT",
     re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*c2VydmljZV9yb2xl[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{10,}")),
    ("secrets.cloudflare", "critical", "Cloudflare API token",
     re.compile(r"""(?i)\b(?:cloudflare|cf)[_-]?(?:api)?[_-]?token\s*[:=]\s*["'][A-Za-z0-9_-]{30,}["']""")),
    ("secrets.vercel", "critical", "Vercel token",
     re.compile(r"""(?i)\bvercel[_-]?(?:api)?[_-]?token["']?\s*[:=]\s*["'][A-Za-z0-9_-]{20,}["']""")),
    ("secrets.azure_storage", "critical", "Azure Storage connection string",
     re.compile(r"AccountKey=[A-Za-z0-9+/=]{60,}")),
    ("secrets.aws_key", "critical", "AWS Access Key",
     re.compile(r"\bAKIA[0-9A-Z]{16}")),
    ("secrets.telegram_bot", "critical", "Telegram bot token",
     re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}")),
    ("secrets.jwt_literal", "critical", "JWT в коде",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("secrets.npmrc_token", "critical", "Токен npm в .npmrc",
     re.compile(r"(?m)^[ \t]*_auth(Token)?[ \t]*=[ \t]*\S{8,}")),
    ("secrets.dotnetrc_pass", "critical", "Пароль в .netrc/.pypirc",
     re.compile(r"(?im)^[ \t]*(?:password|passwd|api_key)[ \t]*[:=][ \t]*\S{6,}")),
    ("secrets.generic_assign", "warning", "Похоже на захардкоженный секрет",
     re.compile(r"""(?i)\b(api[_-]?key|secret|password|token)\b\s*[:=]\s*["'][^"'\s]{16,}["']""")),
]

# файлы, где секретам "можно" (примеры, локи, документация)
SECRET_OK_FILES = re.compile(
    r"(\.example|\.sample|\.template|\.test\.|_test\.|\.spec\.|_spec\.|\.lock$"
    r"|package-lock\.json$|yarn\.lock$|pnpm-lock\.yaml$|\.md$|/fixtures?/|/mocks?/)")
# JWT-литерал и закоммиченные примеры не показываем в тестах
TEST_FILE = re.compile(r"(?i)(test|spec|fixture|mock|example|e2e)")

CLIENT_HINTS = re.compile(r"(src|app|pages|components|public|client)")
CLIENT_SUFFIX = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro", ".html"}
CLIENT_API_CALLS = re.compile(r"""https?://api\.(openai|anthropic|stripe)\.com""")
PUBLIC_ENV = re.compile(
    r"\b(NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_)[A-Z0-9_]*"
    r"(SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)")

FIX_ROTATE = ("Убери из кода, положи в переменную окружения/секрет-менеджер "
              "и ПЕРЕВЫПУСТИ ключ — он уже скомпрометирован, если попадал в git.")


def _iter(root):
    """Файлы, в которых вообще ищем секреты (шире, чем обычный обход кода)."""
    for path, text in core.iter_files(root):
        yield path, text


def git_tracked_set(root):
    """Множество файлов под контролем git (относительные пути). None, если не git-репо."""
    if not (root / ".git").exists():
        return None
    try:
        out = subprocess.run(GIT_SAFE + ["-C", str(root), "ls-files"],
                             capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return set(out.splitlines())


def check_secrets(root, findings):
    tracked = git_tracked_set(root)
    for path, text in _iter(root):
        rel = core.rel_of(path, root)
        allow_soft = bool(SECRET_OK_FILES.search(rel))
        # .env, который НЕ закоммичен — норма (секреты и должны жить локально в .env).
        # Отдельно .env-в-git ловит check_git_env как critical.
        is_env = path.name.startswith(".env")
        if is_env and tracked is not None and rel not in tracked:
            continue
        claimed = set()
        for pid, sev, title, rx in SECRET_PATTERNS:
            if pid in ("secrets.jwt_literal", "secrets.npmrc_token", "secrets.dotnetrc_pass"):
                if pid == "secrets.jwt_literal" and TEST_FILE.search(rel):
                    continue
                if pid == "secrets.npmrc_token" and path.name != ".npmrc":
                    continue
                if pid == "secrets.dotnetrc_pass" and path.name not in (".netrc", ".pypirc"):
                    continue
            for m in rx.finditer(text):
                if allow_soft:
                    break
                ln = core.line_of(text, m.start())
                if ln in claimed:
                    continue
                claimed.add(ln)
                note = " (git не найден — если .env не коммитится, это норма)" \
                    if (is_env and tracked is None) else ""
                findings.append({
                    "id": pid, "severity": sev, "title": title,
                    "where": "{}:{}".format(rel, ln),
                    "detail": "найдено: `{}`{}".format(core.mask(m.group(0)), note),
                    "fix": FIX_ROTATE,
                })


def check_git_env(root, findings):
    tracked = git_tracked_set(root)
    if tracked is None:
        return
    for f in sorted(tracked):
        name = f.replace("\\", "/").rsplit("/", 1)[-1]
        if name.startswith(".env") and not name.endswith((".example", ".sample", ".template")):
            findings.append({
                "id": "secrets.env_in_git", "severity": "critical",
                "title": ".env закоммичен в git",
                "where": f,
                "detail": "файл с секретами отслеживается git",
                "fix": "git rm --cached " + f + "; добавь .env* в .gitignore; "
                       "перевыпусти все ключи из файла; для чистки истории — git filter-repo.",
            })
    gi = root / ".gitignore"
    gi_text = gi.read_text(encoding="utf-8", errors="replace") if gi.exists() else ""
    if ".env" not in gi_text:
        findings.append({
            "id": "secrets.gitignore_env", "severity": "warning",
            "title": ".env не в .gitignore",
            "where": ".gitignore",
            "detail": "рано или поздно кто-то закоммитит секреты",
            "fix": "Добавь строки: .env и .env.*",
        })


def check_client_exposure(root, findings):
    for path, text in core.iter_files(root):
        rel = core.rel_of(path, root)
        if not CLIENT_HINTS.search(rel) or path.suffix.lower() not in CLIENT_SUFFIX:
            continue
        for m in CLIENT_API_CALLS.finditer(text):
            findings.append({
                "id": "secrets.client_api", "severity": "critical",
                "title": "Платный API вызывается из клиента",
                "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                "detail": "прямой вызов {} из фронтенда — ключ виден любому в DevTools".format(m.group(0)),
                "fix": "Вынеси вызов на свой бэкенд/edge-функцию; ключ живёт только на сервере.",
            })
        for m in PUBLIC_ENV.finditer(text):
            if core.is_comment_or_pattern(text, m.start()):
                continue
            findings.append({
                "id": "secrets.public_env_secret", "severity": "critical",
                "title": "Секрет в публичной env-переменной",
                "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                "detail": "{} — префикс делает переменную частью клиентского бандла".format(m.group(0)),
                "fix": "Публичные префиксы (NEXT_PUBLIC_/VITE_/REACT_APP_/PUBLIC_/EXPO_PUBLIC_) "
                       "только для несекретных значений. Секрет — на сервер.",
            })
