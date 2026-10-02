#!/usr/bin/env python3
"""checks_infra.py — CI/CD, контейнеры, Terraform, supply chain, MCP-конфиги, зависимости."""

import json
import os
import re
import shutil
import subprocess

import audit as core

# --- GitHub Actions -------------------------------------------------------

GHA_PR_TARGET = re.compile(r"(?i)^\s*(?:-\s*)?pull_request_target\s*:", re.M)
GHA_CHECKOUT = re.compile(
    r"""(?is)actions/checkout@[\w.-]+\s*(?:\n[^\n]*){0,12}?ref:\s*["']?\$\{\{\s*github\.event\.pull_request"""
    r"""|actions/checkout@[\w.-]+[\s\S]{0,400}?ref:\s*["']?\$\{\{\s*github\.head_ref""")
GHA_SECRET_ECHO = re.compile(r"""(?i)\b(?:echo|print)\b[^\n]{0,120}secrets\.""")
GHA_RUN = re.compile(r"(?i)^\s*(?:run|- run):", re.M)
GHA_WRITE_ALL = re.compile(r"(?im)^\s*permissions\s*:\s*write-all\s*$")
GHA_SELF_HOSTED = re.compile(r"(?i)runs-on\s*:[^\n]*self-hosted")
GHA_PUBLIC_REPO = re.compile(r"(?i)github\.event\.repository\.(private|visibility)")
GHA_UNPINNED = re.compile(r"(?m)^\s*-?\s*uses\s*:\s*([\w.-]+/[\w./-]+)@(main|master|v?\d+(\.\d+)?)\s*$")


def _read(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def check_github_actions(root, findings):
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return
    for wf in sorted(wf_dir.glob("*.y*ml")):
        rel = core.rel_of(wf, root)
        text = _read(wf)
        if not text:
            continue
        if GHA_PR_TARGET.search(text) and GHA_CHECKOUT.search(text):
            findings.append({
                "id": "infra.pr_target_checkout", "severity": "critical",
                "title": "pull_request_target + checkout PR — крадут секреты",
                "where": rel,
                "detail": "на проверку не нужно: триггер даёт секреты, а код берётся из чужой ветки — "
                          "из pull request можно дописать в workflow вывод секретов (классическая схема кражи)",
                "fix": "Не используй pull_request_target с checkout чужого ref. "
                       "Для проверки PR — pull_request без секретов, а сборку делай после merge.",
            })
        run_lines = [text.count("\n", 0, m.start()) + 1 for m in GHA_RUN.finditer(text)]
        for m in GHA_SECRET_ECHO.finditer(text):
            ln = core.line_of(text, m.start())
            if run_lines and not any(abs(ln - r) <= 2 for r in run_lines):
                continue
            findings.append({
                "id": "infra.ci_secret_echo", "severity": "critical",
                "title": "Секрет выводится в лог CI",
                "where": "{}:{}".format(rel, ln),
                "detail": "значение secrets.* попадает в echo/print внутри run — оно попадёт в лог, "
                          "в который у всех Workflow есть доступ",
                "fix": "Не печатай secrets.* и их производные. Маскируй значение или вообще убери вывод.",
            })
        if GHA_WRITE_ALL.search(text):
            findings.append({
                "id": "infra.ci_write_all", "severity": "warning",
                "title": "permissions: write-all в workflow",
                "where": rel,
                "detail": "токену выданы права на запись во все репозитории и пакеты",
                "fix": "Опиши минимальные permissions: contents: read, и расширяй точечно по надобности.",
            })
        if GHA_SELF_HOSTED.search(text) and GHA_PUBLIC_REPO.search(text) is None:
            findings.append({
                "id": "infra.selfhosted_runner", "severity": "warning",
                "title": "self-hosted раннер в публичном репозитории",
                "where": rel,
                "detail": "на проверку: workflow без приватности — вкладчик с правом PR выполняет код на твоей машине",
                "fix": "Держи self-hosted раннер только в приватных репо и на изолированной машине без доступа к секретам.",
            })
        for m in GHA_UNPINNED.finditer(text):
            findings.append({
                "id": "infra.action_not_pinned", "severity": "warning",
                "title": "Action не закреплён по коммиту",
                "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                "detail": "{}@{} — ветка может сместиться и принести вредный код".format(m.group(1), m.group(2)),
                "fix": "Закрепляй action по SHA коммита (actions/checkout@<sha> # v4.x.y).",
            })


# --- Docker / compose / Terraform ----------------------------------------

DOCKER_PRIV = re.compile(r"(?im)^\s*privileged\s*:\s*true")
DOCKER_HOST_NET = re.compile(r"(?im)^\s*network_mode\s*:\s*['\"]?host")
DOCKER_PUB_DB = re.compile(
    r"""(?m)^\s*-\s*["']?(5432|3306|27017|6379|9200|5672):(5432|3306|27017|6379|9200|5672)""")
DOCKER_DEFAULT_PASS = re.compile(
    r"(?i)(POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|REDIS_PASSWORD)"
    r"\s*[:=]\s*[\"']?(postgres|root|password|admin|123|example|changeme)")
COMPOSE_GLOB = ("docker-compose*.yml", "docker-compose*.yaml", "compose.yml", "compose.yaml")


def _dockerfiles(root):
    for p in sorted(root.rglob("Dockerfile*")):
        if core.skip_path(p):
            continue
        yield p
    for p in sorted(root.rglob("*.dockerfile")):
        if core.skip_path(p):
            continue
        yield p


def check_docker(root, findings):
    for df in _dockerfiles(root):
        rel = core.rel_of(df, root)
        text = _read(df)
        if not text:
            continue
        if re.search(r"(?im)^\s*USER\s+\S", text) is None and re.search(
                r"(?im)^\s*(?:RUN|apt-get|apk|add-apk|dnf|yum)\b", text):
            findings.append({
                "id": "infra.docker_no_user", "severity": "warning",
                "title": "Dockerfile ставит пакеты, но не задаёт USER",
                "where": rel,
                "detail": "контейнер работает от root — при пробое приложения злоумышленник получает root в контейнере",
                "fix": "Добавь непривилегированного пользователя и переключись на него: "
                       "RUN adduser ... / USER app.",
            })
        for m in re.finditer(r"(?im)^[ \t]*(?:ARG|ENV)[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*(=[^\n]*)?",
                             text):
            var = m.group(1)
            if not re.search(r"(?i)(secret|token|password|api_?key|credential)", var):
                continue
            value = (m.group(2) or "").strip().strip("\"'")
            if len(value) < 12 or value.startswith("$"):
                continue
            findings.append({
                "id": "infra.docker_secret_arg", "severity": "critical",
                "title": "Секрет зашит в ARG/ENV Dockerfile",
                "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                "detail": "{} = {} — попадёт в слои образа и в docker history".format(
                    var, core.mask(value)),
                "fix": "Не передавай секреты через ARG/ENV. Доставляй их в рантайме "
                       "(docker secret, файл или переменная окружения).",
            })
        for m in re.finditer(r"(?i)curl\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b", text):
            findings.append({
                "id": "infra.docker_curl_pipe_sh", "severity": "warning",
                "title": "curl … | sh в Dockerfile",
                "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                "detail": "на проверку: исполняется всё, что отдаст зеркало прямо в момент сборки",
                "fix": "Скачай файл, проверь чек-сумму и только потом запускай.",
            })
        for m in re.finditer(r"(?im)^\s*ADD\s+(https?://\S+)", text):
            findings.append({
                "id": "infra.docker_add_url", "severity": "warning",
                "title": "ADD с URL в Dockerfile",
                "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                "detail": "ADD не проверяет содержимое удалённого файла и не кешируется",
                "fix": "Используй RUN curl -o с проверкой sha256, либо COPY для локальных файлов.",
            })
        for m in re.finditer(r"(?im)^\s*FROM\s+(\S+):latest\b", text):
            findings.append({
                "id": "infra.docker_from_latest", "severity": "warning",
                "title": "Базовый образ :latest",
                "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                "detail": "сборка не воспроизводима и может внезапно получить скомпрометированный образ",
                "fix": "Закрепи тег версии и (лучше) digest: FROM node:22.11-bookworm@sha256:…",
            })
        for m in re.finditer(r"(?i)\bchmod\s+(-[a-zA-Z]+\s+)*777\b", text):
            findings.append({
                "id": "infra.docker_chmod_777", "severity": "warning",
                "title": "chmod 777 в образе",
                "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                "detail": "любой процесс в контейнере получает права на запись в файлы",
                "fix": "Давай минимальные права: chmod 750/755 и отдельному пользователю — chown.",
            })

    seen = set()
    for pattern in COMPOSE_GLOB:
        for comp in sorted(root.rglob(pattern)):
            if comp in seen or core.skip_path(comp):
                continue
            seen.add(comp)
            rel = core.rel_of(comp, root)
            text = _read(comp)
            if not text:
                continue
            if DOCKER_PRIV.search(text):
                findings.append({
                    "id": "infra.docker_privileged", "severity": "critical",
                    "title": "privileged: true в контейнере",
                    "where": rel,
                    "detail": "контейнер почти равносилен root на хосте: виден /dev, управляется systemd и т.п.",
                    "fix": "Убери privileged. Если нужен доступ к устройству — точечно задай cap_add/device.",
                })
            if DOCKER_HOST_NET.search(text):
                findings.append({
                    "id": "infra.docker_host_net", "severity": "warning",
                    "title": "network_mode: host",
                    "where": rel,
                    "detail": "сервис выходит в сеть хоста напрямую, минуя сетевую изоляцию",
                    "fix": "Используй обычную bridge-сеть и публикуй только нужные порты.",
                })
            if DOCKER_DEFAULT_PASS.search(text):
                findings.append({
                    "id": "infra.docker_default_pass", "severity": "critical",
                    "title": "Дефолтный пароль БД в compose",
                    "where": rel,
                    "detail": "пароль из типового списка (postgres/root/password)",
                    "fix": "Подставь пароль через env/секрет и сгенерируй его случайно.",
                })
            if DOCKER_PUB_DB.search(text):
                findings.append({
                    "id": "infra.docker_db_port", "severity": "warning",
                    "title": "Порт БД проброшен наружу",
                    "where": rel,
                    "detail": "база доступна с хоста (и за ним из интернета, если хост публичный)",
                    "fix": "Не публикуй порт БД; обращайся к ней по внутренней сети compose.",
                })

    for tf in sorted(root.rglob("*.tfvars")):
        if core.skip_path(tf):
            continue
        rel = core.rel_of(tf, root)
        text = _read(tf)
        for m in re.finditer(
                r"""(?im)^\s*(\w*(?:password|secret|token|access_key|private_key)\w*)\s*=\s*"""
                r"""["']([^"'\s$]{12,})["']""", text):
            findings.append({
                "id": "infra.tfvars_secret", "severity": "critical",
                "title": "Секрет литералом в *.tfvars",
                "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                "detail": "{} = {} — terraform хранит состояние открытым текстом".format(
                    m.group(1), core.mask(m.group(2))),
                "fix": "Держи секреты в переменных/менеджере секретов, а в .tfvars подставляй "
                       "TF_VAR_* из окружения.",
            })


def check_platform_configs(root, findings):
    """Блок правил Firebase и их эквивалентов."""
    for rules_name in ("firestore.rules", "storage.rules", "database.rules.json"):
        rf = root / rules_name
        if not rf.exists():
            continue
        rtext = _read(rf)
        if re.search(r"""allow\s+(read|write|read,\s*write)\s*:\s*if\s+true""", rtext) or \
                re.search(r'"\.(read|write)"\s*:\s*true', rtext):
            findings.append({
                "id": "infra.firebase_open", "severity": "critical",
                "title": "Firebase: открытые правила в {}".format(rules_name),
                "where": rules_name,
                "detail": "allow read/write: if true — база открыта всему интернету",
                "fix": "Закрой правила: доступ только аутентифицированным и только к своим данным "
                       "(request.auth.uid == resource.data.owner).",
            })


# --- Supply chain ---------------------------------------------------------

PKG_GIT_URL = re.compile(
    r"""(?i)["'](?:git\+(?:ssh|https?)://|git://|https?://(?:github\.com|gitlab\.com)/[^"'\s]+\.git"""
    r"""|https?://\S+\.(?:tgz|tar\.gz))[^"'\s]*["']""")
NPM_FOREIGN_TARBALL = re.compile(
    r"(?i)https?://(?!registry\.npmjs\.org)[a-z0-9.-]+/(?:[^\s\"']*/)?[^\s\"']+\.tgz")


def check_supply_chain(root, findings):
    pkg = root / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        scripts = data.get("scripts") or {}
        if isinstance(scripts, dict):
            for name, body in scripts.items():
                if not isinstance(body, str):
                    continue
                if name == "postinstall" or name.startswith("postinstall:"):
                    findings.append({
                        "id": "infra.postinstall", "severity": "warning",
                        "title": "postinstall-скрипт в package.json",
                        "where": "package.json",
                        "detail": "выполняется автоматически при npm install — в том числе в CI и у разработчика",
                        "fix": "Убери postinstall, если он не обязателен, либо замени на явный скрипт, "
                               "который запускают руками.",
                    })
                for m in re.finditer(r"(?i)curl\b[^\n|]{0,200}\|\s*(?:ba|z|k)?sh\b", body):
                    findings.append({
                        "id": "infra.script_curl_pipe_sh", "severity": "warning",
                        "title": "curl … | sh в npm-скрипте",
                        "where": "package.json",
                        "detail": "на проверку: скрипт тянет и исполняет код из сети при каждой установке",
                        "fix": "Замени на установку конкретной версии пакета.",
                    })
                for m in re.finditer(r"(?i)\bnpx\s+-y\b", body):
                    findings.append({
                        "id": "infra.script_npx_y", "severity": "warning",
                        "title": "npx -y в npm-скрипте",
                        "where": "package.json",
                        "detail": "-y без подтверждения: скачается и запустится последняя версия пакета",
                        "fix": "Добавь пакет в devDependencies и вызывай его локально, без npx -y.",
                    })
        deps = {}
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            block = data.get(field)
            if isinstance(block, dict):
                deps.update(block)
        for name, spec in sorted(deps.items()):
            if isinstance(spec, str) and PKG_GIT_URL.search(spec):
                findings.append({
                    "id": "infra.dep_from_git", "severity": "warning",
                    "title": "Зависимость ставится с git/URL",
                    "where": "package.json ({})".format(name),
                    "detail": "версия {} — код приходит мимо реестра, без проверки целостности".format(
                        core.mask(spec)),
                    "fix": "Бери пакет из реестра версией. Если нужен форк — опубликуй его в реестр "
                           "или vendорь в репозиторий с проверкой.",
                })
            elif isinstance(spec, str) and NPM_FOREIGN_TARBALL.search(spec):
                findings.append({
                    "id": "infra.dep_foreign_host", "severity": "warning",
                    "title": "Зависимость с чужого хоста",
                    "where": "package.json ({})".format(name),
                    "detail": "URL тарбола указывает не на registry.npmjs.org",
                    "fix": "Используй реестр: npm install {}@<версия>.".format(name),
                })
        lock = any((root / n).exists() for n in
                   ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "npm-shrinkwrap.json"))
        if deps and not lock:
            findings.append({
                "id": "infra.no_lockfile", "severity": "info",
                "title": "Нет lock-файла",
                "where": "package.json",
                "detail": "без фиксации версий сборка не воспроизводима и возможен неожиданный апдейт",
                "fix": "Закоммить package-lock.json (npm ci) или pnpm-lock.yaml.",
            })
    py = root / "requirements.txt"
    if py.exists():
        for m in re.finditer(
                r"""(?im)^([A-Za-z0-9_.-]+)\s*(?:@\s*([^\s;]+)|([=><!~]=?|\s)\s*([^\s;#]+))""",
                _read(py)):
            url = m.group(2) or ""
            if re.search(r"(?i)^(https?|git\+)", url):
                findings.append({
                    "id": "infra.py_dep_url", "severity": "info",
                    "title": "python-зависимость ставится по URL",
                    "where": "requirements.txt",
                    "detail": "{} — версия не из PyPI, код приходит напрямую".format(m.group(1)),
                    "fix": "Опубликуй пакет на PyPI или закрепи зафиксированный commit-хеш.",
                })


# --- MCP / agent configs --------------------------------------------------

MCP_FILES = (".mcp.json", "mcp.json", "mcp_settings.json", "cline_mcp_settings.json")
MCP_ENV_BLOCK = re.compile(
    r'''(?i)"(?:env|environment|config)"\s*:\s*\{[^{}]{0,4000}?\}(?=[\s,}\]])''')
MCP_SECRET_IN_ENV = re.compile(
    r'''(?i)"([^"]*(?:secret|token|key|password|credential)[^"]*)"\s*:\s*"([^"$\n]{12,})"''')


def check_mcp_configs(root, findings):
    for name in MCP_FILES:
        for path in [root / name] + sorted(root.rglob(name)):
            if core.skip_path(path):
                continue
            text = _read(path)
            if not text:
                continue
            rel = core.rel_of(path, root)
            for m in MCP_ENV_BLOCK.finditer(text):
                for k in MCP_SECRET_IN_ENV.finditer(m.group(0)):
                    findings.append({
                        "id": "infra.mcp_secret", "severity": "critical",
                        "title": "Секрет в конфиге MCP/агента",
                        "where": "{}:{}".format(rel, core.line_of(text, m.start() + k.start())),
                        "detail": "{} = {} — конфиг агента обычно коммитится и попадает "
                                  "в репозиторий".format(k.group(1), core.mask(k.group(2))),
                        "fix": "Вынеси значение в переменную окружения: "
                               '"key": "${MY_TOKEN}".',
                    })


# --- Dependency audit -----------------------------------------------------

def _which(name):
    """Кроссплатформенный поиск бинаря (на Windows без .cmd это не найдётся)."""
    found = shutil.which(name)
    if found:
        return found
    if os.name == "nt":
        for ext in (".cmd", ".bat", ".exe"):
            alt = shutil.which(name + ext)
            if alt:
                return alt
    return None


def check_deps(root, findings):
    if (root / "package.json").exists():
        npm = _which("npm")
        if not npm:
            findings.append({
                "id": "infra.npm_missing", "severity": "info",
                "title": "npm audit не запускался",
                "where": "package.json",
                "detail": "npm не найден в PATH — проверка зависимостей пропущена (это НЕ «всё чисто»)",
                "fix": "Установи Node.js и прогони npm audit --json вручную.",
            })
        else:
            try:
                r = subprocess.run(
                    [npm, "audit", "--json", "--ignore-scripts", "--no-fund", "--no-audit-fund"],
                    cwd=str(root), capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=180)
                data = json.loads(r.stdout or "{}")
                meta = (data.get("metadata") or {}).get("vulnerabilities") or {}
                crit, high = meta.get("critical", 0), meta.get("high", 0)
                if crit or high:
                    findings.append({
                        "id": "infra.npm_vulns", "severity": "critical" if crit else "warning",
                        "title": "Уязвимые npm-зависимости",
                        "where": "package.json",
                        "detail": "critical: {}, high: {}".format(crit, high),
                        "fix": "npm audit fix; что не чинится — обнови мажорно или замени пакет.",
                    })
                if r.returncode not in (0, 1) and not meta:
                    findings.append({
                        "id": "infra.npm_audit_failed", "severity": "info",
                        "title": "npm audit не отработал",
                        "where": "package.json",
                        "detail": "код выхода {}, скорее всего нет сети или registry".format(r.returncode),
                        "fix": "Прогони npm audit локально при наличии сети.",
                    })
            except subprocess.TimeoutExpired:
                findings.append({
                    "id": "infra.npm_audit_timeout", "severity": "info",
                    "title": "npm audit не ответил вовремя",
                    "where": "package.json",
                    "detail": "процесс убит по таймауту 180 с — проверка неполная",
                    "fix": "Прогони npm audit вручную.",
                })
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                findings.append({
                    "id": "infra.npm_audit_error", "severity": "info",
                    "title": "npm audit завершился ошибкой",
                    "where": "package.json",
                    "detail": "{}: {}".format(type(exc).__name__, str(exc)[:120]),
                    "fix": "Прогони npm audit вручную.",
                })
    if (root / "requirements.txt").exists() or (root / "pyproject.toml").exists():
        findings.append({
            "id": "infra.py_deps", "severity": "info",
            "title": "Проверь python-зависимости",
            "where": "requirements.txt / pyproject.toml",
            "detail": "автопроверка не встроена, чтобы не тянуть зависимости",
            "fix": "pip install pip-audit && pip-audit",
        })
