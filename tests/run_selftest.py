#!/usr/bin/env python3
"""
run_selftest.py — самотесты vibe-audit: audit.py (сканер) и livecheck.py (сетевая проверка).

Ничего не требует из сети (кроме 127.0.0.1) и ничего не ставит.
Фикстуры лежат в tests/fixtures/ и содержат заглушки __FAKE_*__ — реальные
похожие на ключи строки в репозиторий не кладутся никогда (push protection и
история репозитория). build_fixtures() генерирует корректные по форме значения
во временной копии, где нужен настоящий git-индекс.

Запуск:  python tests/run_selftest.py
Выход:  строки PASS/FAIL на каждое утверждение и итог «N/N — PASS», код 0/1.
"""

import http.server
import io
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SCRIPTS = REPO / "scripts"
AUDIT = SCRIPTS / "audit.py"
LIVECHECK = SCRIPTS / "livecheck.py"
FIXTURES = HERE / "fixtures"

PYTHON = sys.executable or "python"
SUBPROCESS_TIMEOUT = 120
PLACEHOLDER_RE = re.compile(r"__FAKE_[A-Z0-9_]+__")
B64 = string.ascii_letters + string.digits + "+/"
ALNUM = string.ascii_letters + string.digits

RESULTS = []
RUNS = []  # (label, returncode, stdout, stderr) — на них же проверяем отсутствие трейсбеков


# ---------------------------------------------------------------- утилиты

def force_utf8_console():
    """Сама консоль может быть cp1251/cp866 — эмодзи в отчёте не должны ронять тесты."""
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


def rand_text(n, alphabet=ALNUM):
    return "".join(secrets.choice(alphabet) for _ in range(n))


def make_secret(token):
    """Значение нужной формы по имени токена. Ни одно из них не является живым ключом."""
    if "PEM_BODY" in token:
        return "\n".join(rand_text(64, B64) for _ in range(6))
    if "STRIPE" in token:
        return "sk_live_" + rand_text(28)
    if "NPM" in token:
        return "npm_" + rand_text(36)
    return rand_text(40)


def check(name, ok, note=""):
    RESULTS.append((name, bool(ok), note))
    status = "PASS" if ok else "FAIL"
    sys.stdout.write("{}  {}{}\n".format(status, name, "  — " + note if note else ""))
    sys.stdout.flush()
    return bool(ok)


def run(args, env=None, cwd=None, stdin=subprocess.DEVNULL):
    """Запуск дочернего python. Никаких traceback наружу не пропускаем — мы их проверяем."""
    child_env = dict(os.environ)
    # UTF-8-режим Python перебивает PYTHONIOENCODING, а нам нужен настоящий cp1251-консоль.
    child_env.pop("PYTHONUTF8", None)
    if env:
        child_env.update(env)
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.run([PYTHON] + list(args), cwd=cwd or str(HERE), env=child_env,
                          stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=SUBPROCESS_TIMEOUT, creationflags=flags)
    label = " ".join(Path(a).name if a.endswith(".py") else a for a in args[:3])
    RUNS.append((label, proc.returncode, proc.stdout, proc.stderr))
    return proc.returncode, proc.stdout, proc.stderr


def run_audit(path, tmp, extra=None):
    """Прогон сканера с отчётом и JSON во временном каталоге — репозиторий не пачкаем."""
    args = [str(AUDIT), str(path), "--report", str(tmp / "audit-report.md"), "--json"]
    return run(args + list(extra or []))


def parse_json(stdout):
    return json.loads(stdout.decode("utf-8"))


# ---------------------------------------------------------------- фикстуры

def build_fixture(name, dest):
    """Копия фикстуры во временный каталог с подставленными живыми по форме значениями."""
    src = FIXTURES / name
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(str(src), str(dest))
    for path in sorted(dest.rglob("*")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if not PLACEHOLDER_RE.search(text):
            continue
        with open(str(path), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(PLACEHOLDER_RE.sub(lambda m: make_secret(m.group(0)), text))
    return dest


def git_commit(root):
    """Реальный git-индекс: без него проверка «.env в git» не запускается."""
    base = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
            "-c", "user.email=selftest@example.invalid",
            "-c", "user.name=vibe-audit selftest",
            "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"]
    for args in (["init", "-q", str(root)], ["-C", str(root), "add", "-A"],
                 ["-C", str(root), "commit", "-q", "-m", "fixture"]):
        subprocess.run(base + args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=SUBPROCESS_TIMEOUT,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


# ---------------------------------------------------------------- audit.py

BROKEN_EXPECTED = [
    "secrets.env_in_git",          # .env закоммичен
    "secrets.stripe_live",         # ключ в .env, Dockerfile и клиенте
    "secrets.private_key",         # PEM в репозитории
    "secrets.npm_token",          # токен в .npmrc
    "secrets.public_env_secret",   # NEXT_PUBLIC_-секрет
    "secrets.gitignore_env",       # .env не в .gitignore
    "infra.pr_target_checkout",    # pull_request_target + checkout чужого ref
    "infra.ci_secret_echo",        # echo secrets.*
    "infra.docker_secret_arg",     # секрет в ARG Dockerfile
    "infra.docker_privileged",     # privileged: true
    "code.tls_verify_false",       # verify=False
    "code.cors_star",              # CORS *
    "code.math_random_secret",     # Math.random() для OTP
    "code.shell_exec_interpolated",  # exec с подстановкой
]


def test_audit_broken(tmp):
    root = build_fixture("broken", tmp / "broken")
    git_commit(root)
    rc, out, err = run_audit(root, tmp)
    ok_json = True
    payload = {}
    try:
        payload = parse_json(out)
    except (ValueError, UnicodeDecodeError) as exc:
        ok_json = False
        err_note = str(exc)
    else:
        err_note = ""
    check("audit: broken — JSON валиден", ok_json, err_note)
    ids = {f["id"] for f in payload.get("findings", [])}
    missing = [i for i in BROKEN_EXPECTED if i not in ids]
    check("audit: broken — все ожидаемые находки", not missing,
          "нет: " + ", ".join(missing) if missing else
          "{} находок".format(len(payload.get("findings", []))))
    check("audit: broken — код выхода 2 (есть critical)",
          rc == 2 and payload.get("totals", {}).get("critical", 0) > 0,
          "rc={} critical={}".format(rc, payload.get("totals", {}).get("critical")))
    shape_ok = all(set(f) >= {"id", "severity", "title", "where", "detail", "fix"}
                   and f["severity"] in ("critical", "warning", "info")
                   and "\n" not in f["fix"]
                   for f in payload.get("findings", []))
    check("audit: форма находок {id,severity,title,where,detail,fix}", shape_ok)
    masked = not any("sk_live_" in f.get("detail", "").replace("sk_live_", "", 1)
                     and len(re.sub(r"\W", "", f.get("detail", ""))) > 40
                     for f in payload.get("findings", []))
    check("audit: секрет не печатается целиком", masked)
    return root


def test_audit_gia(tmp):
    root = build_fixture("gia-bad", tmp / "gia-bad")
    git_commit(root)
    rc, out, _err = run_audit(root, tmp)
    payload = parse_json(out)
    ids = {f["id"] for f in payload.get("findings", [])}
    check("audit: gia-bad — пойман pull_request_target + checkout PR",
          "infra.pr_target_checkout" in ids and rc == 2, "rc={}".format(rc))


def test_audit_clean(tmp):
    root = build_fixture("clean", tmp / "clean")
    git_commit(root)
    rc, out, _err = run_audit(root, tmp)
    payload = parse_json(out)
    totals = payload.get("totals", {})
    check("audit: clean — 0 critical / 0 warning",
          totals.get("critical") == 0 and totals.get("warning") == 0 and rc == 0,
          "critical={} warning={} info={} rc={}".format(
              totals.get("critical"), totals.get("warning"), totals.get("info"), rc))
    if totals.get("critical") or totals.get("warning"):
        noisy = [f"{f['id']} @ {f['where']}" for f in payload.get("findings", [])
                 if f["severity"] in ("critical", "warning")]
        check("audit: clean — нет шума", False, "; ".join(noisy[:12]))
    return root


def test_audit_exit_codes(tmp, clean_root):
    # 0 — чисто
    rc, _out, _err = run_audit(clean_root, tmp)
    check("audit: код 0 на чистом проекте", rc == 0, "rc={}".format(rc))

    # 1 — только warning
    warn_dir = tmp / "warn-only"
    warn_dir.mkdir(parents=True, exist_ok=True)
    (warn_dir / "app.py").write_text(
        'CORS_ORIGINS = ["*"]\n\n\ndef view():\n'
        '    return {"Access-Control-Allow-Origin": "*"}\n',
        encoding="utf-8")
    rc, out, _err = run_audit(warn_dir, tmp)
    payload = parse_json(out)
    totals = payload.get("totals", {})
    check("audit: код 1 только на warning",
          rc == 1 and totals.get("critical") == 0 and totals.get("warning") >= 1,
          "rc={} {}".format(rc, totals))

    # 2 — несуществующий путь
    rc, out, _err = run_audit(tmp / "no-such-dir", tmp)
    ok = rc == 2
    try:
        parse_json(out)
    except ValueError:
        ok = False
    check("audit: код 2 на несуществующем пути + валидный JSON", ok, "rc={}".format(rc))

    # Упавшая проверка не должна ронять скан и не должна печатать трейсбек
    wrapper = tmp / "force_check_error.py"
    wrapper.write_text(
        "import importlib.util, sys\n"
        "spec = importlib.util.spec_from_file_location('audit', {audit!r})\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "sys.modules['audit'] = mod\n"
        "spec.loader.exec_module(mod)\n"
        "def boom(root, findings):\n"
        "    raise RuntimeError('synthetic check failure')\n"
        "mod._load_checks = lambda: [boom]\n"
        "mod.main(sys.argv[1:])\n".format(audit=str(AUDIT)),
        encoding="utf-8")
    rc, out, err = run([str(wrapper), str(clean_root), "--report", str(tmp / "ce.md"), "--json"])
    try:
        payload = parse_json(out)
    except ValueError:
        payload = {"findings": []}
    ids = {f["id"] for f in payload.get("findings", [])}
    check("audit: упавшая проверка — info, без трейсбека",
          "audit.check_error" in ids and b"Traceback" not in err and rc == 0,
          "rc={}".format(rc))


def test_audit_self_source(tmp):
    """Собственный исходник сканера находками не считается (SELF_DIR пропускается)."""
    rc, out, _err = run_audit(SCRIPTS, tmp)
    try:
        payload = parse_json(out)
    except ValueError:
        payload = {"findings": ["unparsable"]}
    noisy = [f"{f['id']} @ {f['where']}" for f in payload.get("findings", [])]
    check("audit: на собственном исходнике находок нет",
          rc == 0 and payload.get("findings") == [], "rc={} {}".format(rc, "; ".join(noisy[:5])))
    rc, out, _err = run([str(AUDIT), str(SCRIPTS), "--report", str(tmp / "self.md")])
    text = out.decode("utf-8", "replace")
    check("audit: консоль печатает «Пропущено файлов»",
          "Пропущено файлов" in text, text.strip().splitlines()[-1][:80] if text.strip() else "")


# ---------------------------------------------------------------- livecheck.py

class _Handler(http.server.SimpleHTTPRequestHandler):
    """Отдаёт файлы каталога, а на всё остальное — HTML catch-all как у SPA."""

    serve_dir = None

    def __init__(self, *args, **kwargs):
        kwargs["directory"] = str(self.serve_dir)
        super().__init__(*args, **kwargs)

    def do_GET(self):
        rel = self.path.split("?")[0].split("#")[0].strip("/")
        if rel and (self.serve_dir / Path(rel)).is_file():
            return super().do_GET()
        body = b"<!doctype html><html><body><div id=root>catch-all SPA</div></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # тишина в выводе тестов
        pass


def start_server(serve_dir):
    handler = type("H", (_Handler,), {"serve_dir": Path(serve_dir)})
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, "http://127.0.0.1:{}".format(httpd.server_address[1])


def build_web_root(tmp):
    root = tmp / "web"
    (root / ".well-known").mkdir(parents=True, exist_ok=True)
    (root / ".env").write_text(
        "DATABASE_URL=postgres://u:p@localhost/db\nSTRIPE_SECRET_KEY=sk_live_runtimevalue\n",
        encoding="utf-8")
    (root / ".well-known" / "security.txt").write_text(
        "Contact: mailto:security@example.invalid\nExpires: 2030-01-01T00:00:00Z\n",
        encoding="utf-8")
    (root / "index.html").write_text("<!doctype html><html><body>app</body></html>",
                                     encoding="utf-8")
    (root / "config").mkdir(exist_ok=True)
    (root / "config" / "app.json").write_text('{"name": "demo"}', encoding="utf-8")
    return root


def test_livecheck(tmp):
    httpd, base = start_server(build_web_root(tmp))
    try:
        report = tmp / "livecheck-report.md"
        rc, out, err = run([str(LIVECHECK), base, "--yes-i-own-this",
                            "--report", str(report), "--json"])
        ok_json = True
        try:
            payload = parse_json(out)
        except (ValueError, UnicodeDecodeError) as exc:
            payload = {"findings": []}
            ok_json = False
            note = str(exc)
        else:
            note = ""
        check("livecheck: --json валиден", ok_json, note)
        findings = payload.get("findings", [])
        ids = {f["id"] for f in findings}
        check("livecheck: отданный .env найден как critical",
              "livecheck.env_exposed" in ids
              and any(f["severity"] == "critical" and f["where"].endswith("/.env")
                      for f in findings))
        check("livecheck: catch-all роут не даёт ложной утечки",
              not any("config/config.json" in f["where"] or f["where"].endswith("/api-docs")
                      for f in findings),
              "лишних находок: {}".format(len(findings)))
        check("livecheck: security.txt найден (info)", "livecheck.security_txt" in ids)
        check("livecheck: нет заголовков — есть находки", "livecheck.header_missing" in ids)
        check("livecheck: код 2 при critical", rc == 2, "rc={}".format(rc))
        check("livecheck: отчёт написан", report.exists() and report.stat().st_size > 0)
        check("livecheck: без трейсбеков", b"Traceback" not in err)

        # Свой список путей и лимит запросов
        rc, out, _err = run([str(LIVECHECK), base, "--yes-i-own-this", "--timeout", "3",
                             "--paths", ".env,config/app.json," + ",".join(
                                 "pad/{}".format(i) for i in range(80)),
                             "--report", str(report), "--json"])
        payload2 = parse_json(out)
        probe = payload2.get("probed", {})
        custom = {f["where"].rsplit("/", 1)[-1] for f in payload2.get("findings", [])
                  if f["id"] == "livecheck.custom_path"}
        check("livecheck: --paths уважает потолок запросов",
              rc == 1 and probe.get("requests", 0) <= 40 and probe.get("skipped", 0) > 0
              and ".env" in custom,
              "{} запросов, пропущено {}, код {}".format(
                  probe.get("requests"), probe.get("skipped"), rc))

        # Без подтверждения владения в неинтерактивном окружении — чистая ошибка, не трейсбек
        rc, out, err = run([str(LIVECHECK), base, "--report", str(report), "--json"])
        text = err.decode("utf-8", "replace")
        check("livecheck: без TTY — понятная ошибка и код 2",
              rc == 2 and "--yes-i-own-this" in text and b"Traceback" not in err,
              text.strip().splitlines()[0][:70] if text.strip() else "")

        # Недоступный хост (порт закрыт) — тоже код 2, JSON валиден, без трейсбеков
        rc, out, err = run([str(LIVECHECK), "http://127.0.0.1:9", "--yes-i-own-this",
                            "--timeout", "2", "--report", str(report), "--json"])
        ok = rc == 2 and b"Traceback" not in err
        try:
            parse_json(out)
        except ValueError:
            ok = False
        check("livecheck: недоступный хост — код 2 и валидный JSON", ok, "rc={}".format(rc))

        # Криптографически слабный HSTS — warning, а не молчаливый pass
        weak_root = tmp / "web-weak"
        weak_root.mkdir(exist_ok=True)

        class _Weak(_Handler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Strict-Transport-Security", "max-age=60")
                self.send_header("Set-Cookie", "sid=abc123; Path=/")
                body = b"<html><body>ok</body></html>"
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd2 = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Weak)
        httpd2.daemon_threads = True
        threading.Thread(target=httpd2.serve_forever, daemon=True).start()
        try:
            base2 = "http://127.0.0.1:{}".format(httpd2.server_address[1])
            rc, out, _err = run([str(LIVECHECK), base2, "--yes-i-own-this", "--timeout", "3",
                                 "--report", str(report), "--json"])
            payload3 = parse_json(out)
            ids3 = {f["id"] for f in payload3.get("findings", [])}
            check("livecheck: слабый HSTS и кука без SameSite",
                  "livecheck.hsts_weak" in ids3 and "livecheck.cookie_flags" in ids3,
                  "rc={}".format(rc))
        finally:
            httpd2.shutdown()
            httpd2.server_close()

        # cp1251-консоль: ни UnicodeEncodeError, ни трейсбеков у обоих скриптов
        cp = {"PYTHONIOENCODING": "cp1251"}
        rc, out, err = run([str(AUDIT), str(tmp / "clean"), "--report", str(tmp / "cp.md")], env=cp)
        clean_out = out + err
        rc2, out2, err2 = run([str(LIVECHECK), base, "--yes-i-own-this", "--timeout", "3",
                               "--report", str(report)], env=cp)
        live_out = out2 + err2
        bad = [b"UnicodeEncodeError", b"Traceback", b"UnicodeDecodeError"]
        check("cp1251: audit.py без UnicodeEncodeError/Traceback",
              not any(m in clean_out for m in bad), "rc={}".format(rc))
        check("cp1251: livecheck.py без UnicodeEncodeError/Traceback",
              not any(m in live_out for m in bad), "rc={}".format(rc2))
    finally:
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------- main

def main():
    force_utf8_console()
    if not AUDIT.exists() or not LIVECHECK.exists():
        sys.stderr.write("Не найдены scripts/audit.py или scripts/livecheck.py\n")
        return 1
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="vibe-audit-selftest-") as td:
        tmp = Path(td)
        try:
            test_audit_broken(tmp)
            test_audit_gia(tmp)
            clean_root = test_audit_clean(tmp)
            test_audit_exit_codes(tmp, clean_root)
            test_audit_self_source(tmp)
            test_livecheck(tmp)
        except Exception as exc:  # noqa: BLE001 — падение теста тоже должно быть FAIL
            check("внутренняя ошибка набора тестов: {}: {}".format(type(exc).__name__, exc), False)

    leaked = [label for label, _rc, out, err in RUNS
              if b"Traceback" in out or b"Traceback" in err]
    check("ни один запуск не выпустил Traceback", not leaked, ", ".join(leaked[:5]))

    total = len(RESULTS)
    passed = sum(1 for _n, ok, _note in RESULTS if ok)
    sys.stdout.write("\n{}/{} — {}\n".format(passed, total, "PASS" if passed == total else "FAIL"))
    sys.stdout.write("Время: {:.1f} с, запусков скриптов: {}\n".format(
        time.monotonic() - started, len(RUNS)))
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
