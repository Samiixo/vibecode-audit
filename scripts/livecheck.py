#!/usr/bin/env python3
"""
livecheck.py — проверка ТВОЕГО задеплоенного сайта на типовые публичные утечки.

Делает только обычные безобидные GET-запросы (как браузер): читает security-заголовки,
куки, и проверяет, не отдаются ли наружу файлы, которых там быть не должно (.env, .git).
НЕ атакует, не брутфорсит, не фаззит, не краулит. Аналог securityheaders.com + фиксированный
список путей.

⚠️ Запускай ТОЛЬКО против своего домена. Скрипт требует подтверждения владения.

Запуск:
  python livecheck.py https://мой-сайт.com
  python livecheck.py https://мой-сайт.com --yes-i-own-this   # пропустить вопрос
  python livecheck.py https://мой-сайт.com --yes-i-own-this --json
  python livecheck.py https://мой-сайт.com --yes-i-own-this --paths .env,server-status --timeout 5

Коды выхода: 0 чисто, 1 есть warning, 2 есть critical.
Код 2 также для ошибки запуска/внутренней ошибки — так CI отличает «нашли блокер» от «упало».
"""

import argparse
import io
import json
import re
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from http.cookiejar import CookieJar

VERSION = "2.0.0"
TOOL = "vibe-audit"
UA = "vibe-audit-livecheck/2.0 (+https://github.com/Samiixo/vibecode-audit)"

SEV_ORDER = {"critical": 0, "warning": 1, "info": 2}
SEV_ICON = {"critical": "\U0001F534", "warning": "\U0001F7E1", "info": "\U0001F535"}
SEV_ICON_FALLBACK = {"critical": "[!]", "warning": "[~]", "info": "[i]"}

BODY_LIMIT = 2048  # тело целиком не нужно — только начало
MAX_REQUESTS = 40   # потолок запросов: --paths не должен превращать это в скан
MAX_RUNTIME = 60.0  # суммарный предохранитель, секунды

# Фиксированный список путей (path, severity, id, title, fix). Это НЕ краулер:
# каждый путь запрашивается один раз, ровно одним GET.
LEAK_PATHS = [
    (".env", "critical", "livecheck.env_exposed", "Файл .env читается из интернета — секреты доступны всем"),
    (".env.production", "critical", "livecheck.env_exposed", "Файл .env.production читается из интернета"),
    (".env.bak", "critical", "livecheck.env_exposed", "Резервная копия .env отдаётся наружу"),
    (".env.local", "critical", "livecheck.env_exposed", "Файл .env.local читается из интернета"),
    (".git/config", "critical", "livecheck.git_exposed", "Папка .git отдаётся наружу — исходник и история качаются"),
    (".git/HEAD", "critical", "livecheck.git_exposed", "Папка .git доступна — репозиторий можно склонировать с сервера"),
    ("dump.sql", "critical", "livecheck.db_dump", "Дамп базы лежит в открытом доступе"),
    ("backup.sql", "critical", "livecheck.db_dump", "Дамп базы лежит в открытом доступе"),
    ("wp-config.php.bak", "critical", "livecheck.backup_file", "Резервная копия wp-config.php отдаётся наружу"),
    ("actuator/env", "critical", "livecheck.debug_endpoint", "Spring actuator /env открыт — там переменные окружения"),
    ("actuator/heapdump", "critical", "livecheck.debug_endpoint", "Spring actuator /heapdump открыт — дамп памяти с секретами"),
    ("server-status", "warning", "livecheck.debug_endpoint", "Apache server-status открыт — видны запросы и процессы"),
    ("phpinfo.php", "warning", "livecheck.debug_endpoint", "phpinfo раскрывает конфигурацию сервера"),
    ("swagger-ui.html", "warning", "livecheck.api_docs", "Swagger UI открыт — видны все эндпоинты и их контракты"),
    ("api-docs", "warning", "livecheck.api_docs", "Документация API открыта — карта эндпоинтов публична"),
    ("openapi.json", "warning", "livecheck.api_docs", "openapi.json отдаётся публично — проверь, нет ли там ключей"),
    ("config.json", "warning", "livecheck.config_exposed", "config.json отдаётся публично — проверь, что там нет секретов"),
    ("config/config.json", "warning", "livecheck.config_exposed", "config/config.json отдаётся публично — проверь секреты"),
    ("static/config.json", "warning", "livecheck.config_exposed", "static/config.json отдаётся публично — проверь секреты"),
    (".svn/entries", "critical", "livecheck.vcs_exposed", ".svn/entries отдаётся наружу — доступна вся структура и исходники"),
    (".DS_Store", "info", "livecheck.directory_listing", ".DS_Store виден — по нему видно структуру папок"),
]

LEAK_FIX = "Закрой доступ на уровне сервера/CDN; убери файл из веб-корня или перенеси за nginx."

SECURITY_HEADERS = [
    ("content-security-policy", "warning", "Нет Content-Security-Policy",
     "Защита от XSS/инъекций. Добавь CSP-заголовок."),
    ("strict-transport-security", "warning", "Нет HSTS",
     "Strict-Transport-Security заставляет браузер всегда ходить по HTTPS."),
    ("referrer-policy", "warning", "Нет Referrer-Policy",
     "Добавь Referrer-Policy: strict-origin-when-cross-origin, чтобы URL страницы "
     "не утекал в чужие запросы."),
    ("permissions-policy", "info", "Нет Permissions-Policy",
     "Добавь Permissions-Policy и отключи браузерные API, которые приложению не нужны."),
    ("x-frame-options", "info", "Нет X-Frame-Options",
     "Защита от кликджекинга (встраивание твоего сайта в чужой iframe)."),
    ("x-content-type-options", "info", "Нет X-Content-Type-Options",
     "nosniff мешает браузеру угадывать MIME-типы."),
]

# security.txt — позитивная проверка: отсутствие это info, а не ошибка.
SECURITY_TXT = ".well-known/security.txt"
SECURITY_TXT_FIX = ("Опубликуй /.well-known/security.txt: куда писать об уязвимостях, "
                    "сроки ответа и контакты. Это снимает часть агрессии у исследователей.")

HSTS_MAXAGE_RE = re.compile(r"(?i)max-age\s*=\s*\"?(\d+)")
HSTS_MIN = 15552000  # 180 дней — меньше этого браузеры почти не держат политику


def force_utf8_console():
    """Эмодзи в консоли cp1251/cp866 роняли скрипт с UnicodeEncodeError."""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None:
            continue
        if getattr(stream, "encoding", None) and \
                str(stream.encoding).lower().replace("-", "") in ("utf8", "utf8mb4"):
            continue
        try:
            setattr(sys, name, io.TextIOWrapper(
                stream.buffer, encoding="utf-8", errors="replace", line_buffering=True))
        except (AttributeError, ValueError, OSError):
            pass


def icon(sev):
    return SEV_ICON.get(sev, SEV_ICON_FALLBACK["info"])


def fetch(url, timeout):
    """Один безобидный GET. Возвращает (code, headers, body_start, jar, final_url)."""
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA})
    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    resp = opener.open(req, timeout=timeout)
    body = resp.read(BODY_LIMIT)  # только начало, нам не нужно тело целиком
    # Ключи заголовков приводим к нижнему регистру: сервер может прислать
    # «Content-type», а не «Content-Type» — иначе проверка молча не срабатывает.
    headers = {k.lower(): v for k, v in resp.headers.items()}
    return resp.getcode(), headers, body, jar, resp.geturl()


def looks_like_catchall(ctype, body, final_url, target):
    """Защита от ложных срабатываний на SPA catch-all роутах."""
    # редирект на другой путь => файл НЕ отдаётся (частый ложный плюс на SPA)
    if final_url.rstrip("/") != target.rstrip("/"):
        return True
    # если вернулся HTML вместо сырого файла — это тоже catch-all роут, не утечка
    if "text/html" in ctype.lower():
        return True
    return body.lstrip()[:14].lower().startswith((b"<!doctype", b"<html"))


def _add(findings, fid, sev, title, where, detail, fix):
    findings.append({"id": fid, "severity": sev, "title": title,
                     "where": where, "detail": detail, "fix": fix})


def check_headers(url, headers, jar, findings):
    hlower = {k.lower(): v for k, v in headers.items()}
    for hkey, sev, title, fix in SECURITY_HEADERS:
        if hkey in hlower:
            continue
        _add(findings, "livecheck.header_missing", sev, title, url,
             "заголовок {} не пришёл в ответе".format(hkey), fix)
    # HSTS есть, но с крошечным max-age — это тихий обход защиты
    hsts = hlower.get("strict-transport-security", "")
    if hsts:
        m = HSTS_MAXAGE_RE.search(hsts)
        if m is None or int(m.group(1)) < HSTS_MIN:
            _add(findings, "livecheck.hsts_weak", "warning",
                 "HSTS без внятного max-age", url,
                 "max-age={} — политика почти не действует, её легко сбросить браузером".format(
                     m.group(1) if m else "нет"),
                 "Поставь Strict-Transport-Security: max-age=31536000; includeSubDomains.")

    for leaky_h in ("server", "x-powered-by"):
        if leaky_h in hlower:
            _add(findings, "livecheck.server_disclosure", "info",
                 "Заголовок {} раскрывает стек".format(leaky_h), url,
                 "{}: {}".format(leaky_h, hlower[leaky_h][:40]),
                 "Скрой версию сервера/фреймворка — она подсказывает известные уязвимости.")

    for cookie in jar:
        flags_missing = []
        if not cookie.secure:
            flags_missing.append("Secure")
        if not (cookie.has_nonstandard_attr("HttpOnly")
                or cookie.has_nonstandard_attr("httponly")):
            flags_missing.append("HttpOnly")
        if not (cookie.has_nonstandard_attr("SameSite")
                or cookie.has_nonstandard_attr("samesite")):
            flags_missing.append("SameSite")
        if not flags_missing:
            continue
        _add(findings, "livecheck.cookie_flags", "warning",
             "Кука '{}' без флагов: {}".format(cookie.name, ", ".join(flags_missing)), url,
             "кука приходит без: {}".format(", ".join(flags_missing)),
             "HttpOnly прячет куку от JS (защита от XSS-кражи), Secure — только по HTTPS, "
             "SameSite=Lax|Strict — не отправляет куку с чужих сайтов.")


def probe_paths(url, paths, timeout, findings):
    """Фиксированный список путей, по одному GET на путь. Краулинга нет."""
    started = time.monotonic()
    probed = 0
    skipped = 0
    budget = min(len(paths), max(0, MAX_REQUESTS - 1))
    for path, sev, fid, title in paths:
        if probed >= budget:
            skipped += 1
            continue
        if time.monotonic() - started > MAX_RUNTIME:
            skipped += 1
            continue
        target = "{}/{}".format(url, path.lstrip("/"))
        probed += 1
        try:
            code, fhead, body, _, final_url = fetch(target, timeout)
        except urllib.error.HTTPError:
            continue  # 403/404 — это хорошо, файл закрыт
        except (urllib.error.URLError, OSError, ValueError):
            continue  # таймаут/сеть — не повод считать это утечкой
        if code != 200 or not body.strip():
            continue
        if looks_like_catchall(fhead.get("content-type", ""), body, final_url, target):
            continue
        _add(findings, fid, sev, title, target,
             "GET {} вернул 200 и не-HTML содержимое ({})".format(
                 path, fhead.get("content-type", "неизвестно").split(";")[0]),
             LEAK_FIX)
    return probed, skipped


def check_security_txt(url, timeout, findings):
    """Позитивная проверка: есть ли security.txt. Отсутствие — info, не ошибка."""
    target = "{}/{}".format(url, SECURITY_TXT)
    try:
        code, _fhead, body, _, final_url = fetch(target, timeout)
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError):
        code, body, final_url = 0, b"", target
    ok = (code == 200 and final_url.rstrip("/") == target.rstrip("/")
          and body.strip()
          and not body.lstrip()[:14].lower().startswith((b"<!doctype", b"<html")))
    if ok:
        _add(findings, "livecheck.security_txt", "info",
             "security.txt на месте", target,
             "файл отдаётся по стандарту RFC 9116", SECURITY_TXT_FIX)
    else:
        _add(findings, "livecheck.security_txt_missing", "info",
             "Нет /.well-known/security.txt", target,
             "это не уязвимость, но исследователю некуда сообщить о проблеме", SECURITY_TXT_FIX)


def _report_lines(url, counts, findings, probed, skipped):
    lines = ["# \U0001F310 vibe-audit livecheck: {}".format(url), "",
             "**{} находок — {} {} критичных, {} {} важных, {} {} на проверку**".format(
                 len(findings), icon("critical"), counts["critical"],
                 icon("warning"), counts["warning"],
                 icon("info"), counts["info"]), "",
             "_Только внешние GET-запросы. Это не пентест — внутреннюю логику так не проверить._", ""]
    for f in findings:
        lines.append("## {} {}".format(icon(f["severity"]), f["title"]))
        lines.append("- URL: `{}`".format(f["where"]))
        if f.get("detail"):
            lines.append("- Детали: {}".format(f["detail"]))
        lines.append("- Как чинить: {}".format(f["fix"]))
        lines.append("")
    if not findings:
        lines.append("Внешних утечек не видно. Хороший знак, но внутреннюю логику это не проверяет.")
    lines.append("")
    lines.append("Запрошено путей: {} (запросов не больше {}), пропущено по лимиту: {}.".format(
        probed, MAX_REQUESTS, skipped))
    lines.append("")
    return lines


def _json_payload(url, counts, findings, exit_code, probe=None):
    return {
        "tool": TOOL,
        "kind": "livecheck",
        "version": VERSION,
        "target": url,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "exit_code": exit_code,
        "totals": {"critical": counts["critical"],
                   "warning": counts["warning"],
                   "info": counts["info"]},
        "probed": probe or {"requests": 0, "skipped": 0, "max_requests": MAX_REQUESTS},
        "findings": findings,
    }


def fail(args, message, url="-", exit_code=2):
    """Ошибка запуска/внутренняя ошибка. Код 2 — как и при critical, но это видно по --json."""
    counts = {"critical": 0, "warning": 0, "info": 0}
    sys.stderr.write("{}\n".format(message))
    if getattr(args, "json", False):
        sys.stdout.write(json.dumps(_json_payload(url, counts, [], exit_code),
                                    ensure_ascii=False, indent=2) + "\n")
    sys.exit(exit_code)


def confirm_ownership(args, url):
    """Вопрос про владение — только в настоящем терминале. В пайпе/CI это ошибка запуска."""
    if args.yes_i_own_this:
        return
    # Терминал = оба потока настоящие терминалы. На Windows isatty() у NUL тоже
    # отвечает True, поэтому одного stdin недостаточно: пайп/CI должен упадать явно.
    interactive = False
    try:
        interactive = bool(sys.stdin) and bool(sys.stdout) \
            and sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError, OSError):
        interactive = False
    if not interactive:
        fail(args,
             "Нет интерактивного терминала: спросить про владение нечем.\n"
             "Если это ТВОЙ сайт — запусти с флагом --yes-i-own-this. "
             "Проверять можно только свои домены.",
             url)
    print("\n{}  Ты собираешься проверить: {}".format("\u26A0\uFE0F", url))
    print("Запускай это ТОЛЬКО против сайта, которым владеешь ты.")
    try:
        ans = input("Это твой сайт? (yes/no): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        fail(args, "Отменено: ответ не получен.", url)
    if ans not in ("yes", "y", "да", "д"):
        fail(args, "Отменено. Проверяй только свои домены.", url)


def main(argv=None):
    force_utf8_console()
    ap = argparse.ArgumentParser(prog="vibe-audit-livecheck",
                                 description="Проверка ТВОЕГО сайта на публичные утечки (только GET)")
    ap.add_argument("url", help="URL ТВОЕГО сайта (https://...)")
    ap.add_argument("--yes-i-own-this", action="store_true",
                    help="подтвердить владение без вопроса")
    ap.add_argument("--report", default="livecheck-report.md")
    ap.add_argument("--json", action="store_true", dest="json",
                    help="напечатать JSON-вывод в stdout (для CI и агентов)")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="таймаут одного запроса, секунд (по умолчанию 10)")
    ap.add_argument("--paths", default=None,
                    help="свой список путей через запятую вместо стандартного")
    args = ap.parse_args(argv)

    url = args.url.rstrip("/")
    if not url.startswith(("http://", "https://")):
        fail(args, "URL должен начинаться с http:// или https://")
    if args.timeout <= 0 or args.timeout > 120:
        fail(args, "--timeout должен быть от 0 до 120 секунд")

    if args.paths:
        wanted = [p.strip().lstrip("/") for p in args.paths.split(",") if p.strip()]
        paths = [(p, "warning", "livecheck.custom_path", "Путь {} отдаётся наружу".format(p))
                 for p in wanted]
        if not paths:
            fail(args, "--paths пустой: перечисли пути через запятую", url)
    else:
        paths = LEAK_PATHS
    # Потолок запросов держит probe_paths: лишние пути он просто помечает пропущенными.

    confirm_ownership(args, url)

    findings = []
    try:
        code, headers, _body, jar, _final = fetch(url, args.timeout)
    except urllib.error.HTTPError as exc:
        fail(args, "{} вернул {} — проверять нечего.".format(url, exc.code), url)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        fail(args, "Не удалось открыть {}: {}".format(url, exc), url)
    except Exception as exc:  # noqa: BLE001 — трейсбек пользователю не нужен
        fail(args, "Внутренняя ошибка запроса: {}: {}".format(type(exc).__name__, exc), url)

    check_headers(url, headers, jar, findings)
    try:
        probed, skipped = probe_paths(url, paths, args.timeout, findings)
        check_security_txt(url, args.timeout, findings)
    except Exception as exc:  # noqa: BLE001
        fail(args, "Внутренняя ошибка проверки путей: {}: {}".format(type(exc).__name__, exc), url)

    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["id"], f["where"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    exit_code = 2 if counts["critical"] else (1 if counts["warning"] else 0)
    probe = {"requests": probed, "skipped": skipped, "max_requests": MAX_REQUESTS}

    if args.json:
        sys.stdout.write(json.dumps(_json_payload(url, counts, findings, exit_code, probe),
                                    ensure_ascii=False, indent=2) + "\n")
    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("\n".join(_report_lines(url, counts, findings, probed, skipped)))
        except OSError as exc:
            sys.stderr.write("Не смог записать отчёт: {}\n".format(exc))
            if not args.json:
                sys.exit(2)
    if not args.json:
        print("\U0001F310 vibe-audit livecheck: {} находок "
              "({} {} / {} {} / {} {}) — запросов: {}".format(
                  len(findings), icon("critical"), counts["critical"],
                  icon("warning"), counts["warning"],
                  icon("info"), counts["info"], probed))
        print("Отчёт: {}".format(args.report))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
