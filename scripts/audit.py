#!/usr/bin/env python3
"""
audit.py — аудит безопасности вайбкод-проекта. Только чтение, ничего не меняет.

Запуск:  python audit.py /путь/к/проекту [--report report.md] [--json]
Выход:   консольная сводка + Markdown-отчёт с severity и фиксами.
Коды выхода: 0 чисто, 1 есть warning, 2 есть critical.
"""

import argparse
import bisect
import io
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

VERSION = "2.0.0"
TOOL = "vibe-audit"

# Корень установки самого скилла (scripts/audit.py → skills/vibe-audit).
# Используется, чтобы не проверять собственные шаблоны сканера.
SELF_DIR = Path(__file__).resolve().parent.parent
_SELF_REAL = os.path.realpath(str(SELF_DIR))

SKIP_DIRS = {".git", "node_modules", ".next", "dist", "build", ".venv", "venv",
             "__pycache__", ".cache", "vendor", "Pods", ".dart_tool", "coverage"}
# Текстовые расширения — плюс всё, что попадает в EXTRA_NAMES ниже.
TEXT_EXT = {".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".php", ".go", ".java",
            ".kt", ".swift", ".vue", ".svelte", ".html", ".css", ".json", ".yml",
            ".yaml", ".toml", ".env", ".sh", ".sql", ".md", ".txt", ".cfg", ".ini",
            ".mjs", ".cjs", ".mts", ".cts", ".astro", ".tf", ".tfvars", ".conf",
            ".service", ".properties", ".xml", ".graphql", ".sql", ".hcl"}
# Файлы без расширения, которые обязаны проверяться (v1 их не открывал вообще).
EXTRA_NAMES = {"Dockerfile", "Makefile", "Procfile", ".npmrc", ".netrc", ".pypirc",
               ".npmignore", ".dockerignore", ".env", "docker-compose.yml", "docker-compose.yaml",
               "compose.yml", "compose.yaml", "Gemfile", "Rakefile", "Vagrantfile"}
EXTRA_SUFFIX = {".pem", ".key", ".p12", ".pfx", ".crt", ".cer", ".keystore", ".jks"}
MAX_FILE = 1_000_000  # 1MB
NUL_SNIFF = 8192

SEV_ORDER = {"critical": 0, "warning": 1, "info": 2}
SEV_ICON = {"critical": "\U0001F534", "warning": "\U0001F7E1", "info": "\U0001F535"}
SEV_ICON_FALLBACK = {"critical": "[!]", "warning": "[~]", "info": "[i]"}

# Примеры/тесты/доки: секреты там ожидаемы, конфиги-проверки тоже дают шум.
SECRET_SOFT_FILE = re.compile(
    r"(?i)(\.example|\.sample|\.template|\.test\.|_test\.|\.spec\.|_spec\.|"
    r"\btests?/|/fixtures?/|/mocks?/|\.md$)")

SKIPPED = []  # (rel, причина) — тихих пропусков быть не должно


# ---------------------------------------------------------------- утилиты

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


def mask(s):
    """Никогда не печатаем секрет целиком."""
    s = s.strip().strip("\"'")
    return s[:6] + "\u2026" + s[-2:] if len(s) > 10 else "***"


_LINECACHE = {}


def line_of(text, pos):
    """Номер строки по смещению. Кэш со смещениями переводов строк: без него
    подсчёт на минифицированном файле был квадратичным по числу находок."""
    key = id(text)
    entry = _LINECACHE.get(key)
    if entry is None or entry[0] is not text:
        if len(_LINECACHE) > 8:
            _LINECACHE.clear()
        offsets = [i for i, ch in enumerate(text) if ch == "\n"]
        entry = (text, offsets)
        _LINECACHE[key] = entry
    offsets = entry[1]
    return bisect.bisect_right(offsets, pos - 1) + 1


def rel_of(path, root):
    """Относительный путь в едином виде — с '/' и с любыми именами файлов."""
    try:
        rel = os.path.relpath(str(path), str(root))
    except ValueError:
        rel = str(path)
    return rel.replace(os.sep, "/")


_COMMENT_CACHE = {}
_PATTERN_LINE = re.compile(r"re\.(?:compile|search|finditer|match|findall)|regex|match\(")


def is_comment_or_pattern(text, pos):
    """Грубая эвристика: находка внутри комментария или определения regex — не считаем.
    Результат кэшируется по строке: на минифицированном файле (одна строка на мегабайт)
    пересчёт стоил бы квадратично."""
    line_start = text.rfind("\n", 0, pos) + 1
    entry = _COMMENT_CACHE.get(id(text))
    if entry is None or entry[0] is not text:
        if len(_COMMENT_CACHE) > 8:
            _COMMENT_CACHE.clear()
        entry = (text, {})
        _COMMENT_CACHE[id(text)] = entry
    cache = entry[1]
    if line_start in cache:
        return cache[line_start]
    line_end = text.find("\n", pos)
    line = text[line_start: line_end if line_end != -1 else len(text)]
    stripped = line.lstrip()
    verdict = (stripped.startswith(("#", "//", "*", "/*", "<!--", "--"))
               or bool(_PATTERN_LINE.search(line)))
    cache[line_start] = verdict
    return verdict


_QUOTECACHE = {}


def in_multiline_string(text, pos):
    """Находится ли позиция внутри многострочного строкового литерала (r\"\"\"…\"\"\")?
    Такие участки — обычно regex-паттерны, документация или SQL, а не исполняемый код."""
    key = id(text)
    entry = _QUOTECACHE.get(key)
    if entry is None or entry[0] is not text:
        if len(_QUOTECACHE) > 8:
            _QUOTECACHE.clear()
        quotes = [m.start() for m in re.finditer(r'(?:"""|\'\'\')', text)]
        entry = (text, quotes)
        _QUOTECACHE[key] = entry
    return bisect.bisect_right(entry[1], pos) % 2 == 1


def _is_texty(path):
    name = path.name
    suffix = path.suffix.lower()
    return (suffix in TEXT_EXT or suffix in EXTRA_SUFFIX or name in EXTRA_NAMES
            or name.startswith(".env"))


def skip_path(path):
    """Единый фильтр путей для всех проверок.

    Служебные каталоги (node_modules, dist, …) пропускаются всегда, а каталог
    самого скилла — потому что его собственные шаблоны и намеренно сломанные
    фикстуры выглядят как находки. Проверки, которые обходят файлы через rglob
    (CI/CD, контейнеры, terraform, MCP), обязаны звать эту функцию, иначе
    self-skip обходится стороной.
    """
    raw = str(path)
    try:
        real = os.path.realpath(raw)
    except (OSError, ValueError):
        return True
    if real == _SELF_REAL or real.startswith(_SELF_REAL + os.sep):
        return True
    return any(part in SKIP_DIRS for part in Path(raw).parts)


def iter_files(root):
    """Отдаёт (path, text). Всё, что пропущено, попадает в SKIPPED — молча не пропускаем."""
    visited = set()
    self_dir = os.path.realpath(str(SELF_DIR))
    reported_self = []
    for dirpath, dirnames, filenames in os.walk(str(root), followlinks=False):
        real = os.path.realpath(dirpath)
        # Сам скилл не проверяем: его собственные шаблоны выглядят как находки.
        # Имя папки тут ни при чём — репо может называться как угодно, поэтому
        # сравниваем с реальным путём установки.
        if (real == self_dir or real.startswith(self_dir + os.sep)):
            if not reported_self:
                reported_self.append(rel_of(dirpath, root))
                _skip(rel_of(dirpath, root), "каталог самого скилла — не проверяется изнутри")
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and d != ".git" and "vibe-audit" not in d]
        if real in visited:  # защита от цикла через junction/симлинк
            dirnames[:] = []
            continue
        visited.add(real)
        for name in filenames:
            path = Path(dirpath) / name
            spath = str(path)
            rel = rel_of(spath, root)
            try:
                st = os.lstat(spath)
            except OSError as exc:
                _skip(rel, "не читается: {}".format(exc.strerror or "ошибка доступа"))
                continue
            if os.path.islink(spath):
                _skip(rel, "симлинк — не читаем целевой файл")
                continue
            if not os.path.isfile(spath):
                continue
            if not _is_texty(path):
                continue
            if st.st_size > MAX_FILE:
                _skip(rel, "файл больше {} МБ ({} КБ) — содержимое не проверялось".format(
                    MAX_FILE // 1000000, st.st_size // 1024))
                continue
            if st.st_size == 0:
                continue
            try:
                with open(spath, "rb") as fh:
                    head = fh.read(NUL_SNIFF)
                    fh.seek(0)
                    raw = fh.read(MAX_FILE + 1)
            except OSError as exc:
                _skip(rel, "не читается: {}".format(exc.strerror or "ошибка доступа"))
                continue
            if b"\x00" in head:
                _skip(rel, "двоичный файл — текстовые проверки неприменимы")
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("utf-8", errors="replace")
            yield path, text


def _skip(rel, reason):
    entry = "{} — {}".format(rel, reason)
    if entry not in SKIPPED:
        SKIPPED.append(entry)


# ---------------------------------------------------------------- вывод

MAX_PER_FILE_AND_ID = 5  # один минифицированный файл не должен утопить отчёт
MAX_FINDINGS = 300


def cap_findings(findings):
    """Ограничивает число однотипных находок по одному файлу и общий объём."""
    seen = {}
    kept = []
    for f in findings:
        key = (f["id"], f["where"].rsplit(":", 1)[0] if ":" in f["where"] else f["where"])
        n = seen.get(key, 0)
        seen[key] = n + 1
        if n < MAX_PER_FILE_AND_ID:
            kept.append(f)
        elif n == MAX_PER_FILE_AND_ID:
            kept.append({
                "id": f["id"] + ".more", "severity": "info",
                "title": "Ещё совпадения того же типа: {}".format(f["title"]),
                "where": key[1],
                "detail": "в файле найдено больше {} однотипных совпадений — смотри вручную".format(
                    MAX_PER_FILE_AND_ID),
                "fix": "Открой файл и пройдись по всем совпадениям.",
            })
    if len(kept) > MAX_FINDINGS:
        extra = len(kept) - MAX_FINDINGS
        kept = kept[:MAX_FINDINGS]
        kept.append({
            "id": "audit.truncated", "severity": "info",
            "title": "Отчёт обрезан",
            "where": "-",
            "detail": "показаны первые {} находок, ещё {} не вошли в отчёт".format(
                MAX_FINDINGS, extra),
            "fix": "Разбей проект на части или отфильтруй вывод по --json.",
        })
    return kept


def _report_lines(root, findings, counts):
    name = os.path.basename(str(root).rstrip("\\/")) or str(root)
    lines = ["# \U0001FA7A vibe-audit: {}".format(name), "",
             "**Итог: {} находок — {} {} критичных, {} {} важных, {} {} на проверку**".format(
                 len(findings), icon("critical"), counts["critical"],
                 icon("warning"), counts["warning"],
                 icon("info"), counts["info"]), ""]
    for f in findings:
        lines.append("## {} {}".format(icon(f["severity"]), f["title"]))
        lines.append("- Где: `{}`".format(f["where"]))
        if f.get("detail"):
            lines.append("- Детали: {}".format(f["detail"]))
        lines.append("- Как чинить: {}".format(f["fix"]))
        lines.append("")
    if not findings:
        lines.append("Чисто. Либо проект образцовый, либо проверь, ту ли папку указал \U0001F642")
    if SKIPPED:
        lines.append("## Пропущено при обходе")
        lines.append("")
        for entry in SKIPPED:
            lines.append("- {}".format(entry))
        lines.append("")
    return lines


def _json_payload(root, findings, counts, exit_code):
    return {
        "tool": TOOL,
        "version": VERSION,
        "root": str(root),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "exit_code": exit_code,
        "totals": {"critical": counts["critical"],
                   "warning": counts["warning"],
                   "info": counts["info"]},
        "skipped": list(SKIPPED),
        "findings": findings,
    }


def _emit(args, root, findings, counts, exit_code):
    as_json = bool(getattr(args, "json", False))
    if as_json:
        payload = _json_payload(root, findings, counts, exit_code)
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    if getattr(args, "report", None):
        lines = _report_lines(root, findings, counts)
        try:
            with open(args.report, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("\n".join(lines))
        except OSError as exc:
            sys.stderr.write("Не смог записать отчёт: {}\n".format(exc))
            if not as_json:
                sys.exit(1)
    if not as_json:
        print("\U0001FA7A vibe-audit: {} находок "
              "({} {} / {} {} / {} {})".format(
                  len(findings), icon("critical"), counts["critical"],
                  icon("warning"), counts["warning"],
                  icon("info"), counts["info"]))
        if args.report:
            print("Отчёт: {}".format(args.report))
        if SKIPPED:
            print("Пропущено файлов: {} (см. отчёт)".format(len(SKIPPED)))


# ---------------------------------------------------------------- main

def _load_checks():
    """Импорт соседних модулей. audit.py запускается как скрипт, поэтому
    sys.path[0] = scripts/ и обычный import работает. Алиас нужен, чтобы
    чек-модули не загрузили вторую копию этого же файла (со своим SKIPPED)."""
    sys.modules.setdefault("audit", sys.modules[__name__])
    import checks_secrets
    import checks_infra
    import checks_code
    return [
        checks_secrets.check_secrets,
        checks_secrets.check_git_env,
        checks_secrets.check_client_exposure,
        checks_infra.check_github_actions,
        checks_infra.check_docker,
        checks_infra.check_platform_configs,
        checks_infra.check_supply_chain,
        checks_infra.check_mcp_configs,
        checks_infra.check_deps,
        checks_code.check_config,
        checks_code.check_tls,
        checks_code.check_auth_crypto,
        checks_code.check_injection,
        checks_code.check_ssrf,
        checks_code.check_framework_config,
        checks_code.check_authz,
        checks_code.check_rate_limit_and_ai,
    ]


def main(argv=None):
    force_utf8_console()
    ap = argparse.ArgumentParser(prog="vibe-audit", description=TOOL)
    ap.add_argument("path", help="корень проекта")
    ap.add_argument("--report", default="vibe-audit-report.md")
    ap.add_argument("--json", action="store_true", dest="json",
                    help="дополнительно напечатать JSON-вывод в stdout")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        # Код 2, а не 1: 1 зарезервирован за «есть warning». Неверный путь —
        # это ошибка запуска, иначе в CI она читается как предупреждение о коде.
        sys.stderr.write("Нет такой папки: {}\n".format(root))
        if args.json:
            sys.stdout.write(json.dumps(_json_payload(root, [], {"critical": 0, "warning": 0,
                                                                "info": 0}, 2),
                                        ensure_ascii=False, indent=2) + "\n")
        sys.exit(2)
    root = Path(root)

    findings = []
    for check in _load_checks():
        try:
            check(root, findings)
        except Exception as exc:  # одна упавшая проверка не должна ронять скан
            findings.append({"id": "audit.check_error", "severity": "info",
                             "title": "Проверка {} не отработала".format(check.__name__),
                             "where": "-",
                             "detail": "{}: {}".format(type(exc).__name__, str(exc)[:200]),
                             "fix": "Сообщи в Issues, приложив вывод."})

    findings = cap_findings(findings)
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["id"], f["where"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    exit_code = 2 if counts["critical"] else (1 if counts["warning"] else 0)
    _emit(args, root, findings, counts, exit_code)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
