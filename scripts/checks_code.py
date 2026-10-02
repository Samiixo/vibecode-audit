#!/usr/bin/env python3
"""checks_code.py — конфиги, auth/crypto, инъекции, SSRF, авторизация, rate limit, AI-расходы."""

import re

import audit as core

CODE_EXT = {".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".php", ".go", ".java", ".mjs", ".cjs"}
CONF_EXT = {".json", ".yml", ".yaml", ".toml", ".sh", ".env", ".ini", ".cfg", ".properties", ".rb"}

# --- базовые конфиг-проверки (из v1) -------------------------------------

CONFIG_CHECKS = [
    ("code.cors_star", "warning", "CORS открыт для всех (*)",
     re.compile(r"""(?i)(Access-Control-Allow-Origin["'\s:,=>]+\*|cors\(\s*\{\s*origin\s*:\s*["']\*"""
                r"""|CORS_ORIGIN\s*=\s*\*|CORS_ORIGINS?\s*=\s*\[\s*["']\*|"""
                r"""allow_origins\s*=\s*\[\s*["']\*)"""),
     "Ограничь origin списком своих доменов."),
    ("code.debug_on", "warning", "Debug-режим в коде",
     re.compile(r"(?i)(\bdebug\s*=\s*True\b|DEBUG\s*=\s*True|"
                r"""["']debug["']\s*:\s*(?:true|["']true["']))"""),
     "Выключи debug в проде: он раскрывает стектрейсы и внутренности."),
    ("code.eval_use", "warning", "eval() на данных",
     re.compile(r"""(?<!['"\w.])eval\s*\("""),
     "eval на пользовательском вводе = исполнение чужого кода. Замени на безопасный парсинг."),
    ("code.sql_fstring", "warning", "SQL через f-строку/конкатенацию",
     re.compile(r"""(?i)(execute|query)\s*\(\s*f["'].*(SELECT|INSERT|UPDATE|DELETE).*\{"""),
     "Используй параметризованные запросы, иначе SQL-инъекция."),
]

# --- TLS-проверка --------------------------------------------------------

TLS_CHECKS = [
    ("code.tls_verify_false", re.compile(r"""(?<![\w.])verify\s*=\s*False\b""")),
    ("code.tls_reject_unauth", re.compile(r"rejectUnauthorized\s*:\s*false")),
    ("code.tls_skip_verify", re.compile(r"insecureSkipVerify\s*:\s*true")),
    ("code.tls_env", re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*[\"']?0\b")),
    ("code.tls_unverified_ctx", re.compile(r"ssl\._create_unverified_context")),
    ("code.tls_curlopt", re.compile(
        r"CURLOPT_SSL_VERIFYPEER\s*[,\s]*0\b|CURLOPT_SSL_VERIFYHOST\s*[,\s]*0\b")),
]

# --- auth & crypto -------------------------------------------------------

MATH_RANDOM_SECRET = re.compile(
    r"(?i)Math\.random\(\s*\)[\s\S]{0,80}?(token|otp|secret|password|reset|nonce|code|salt)")
HASH_FOR_PASSWORD = re.compile(
    r"""(?i)\b(?:md5|sha1)\b[\s\S]{0,40}?(?:password|passwd|pwd)"""
    r"""|(?:password|passwd)[\s\S]{0,40}?\b(?:md5|sha1)\b""")
BCRYPT_WEAK = re.compile(r"(?i)bcrypt\.hash\w*\([^)]*,\s*(?:[1-9])\s*[,)]"
                         r"|rounds\s*[:=]\s*(?:[1-9])\b")
JWT_DECODE = re.compile(r"\bjwt\.decode\s*\(|\bjose\.jwtVerify\s*\(|\bjwt_decode\s*\(")
ALG_NONE = re.compile(r"""["']alg["']\s*:\s*["']none["']|\ballowed_algs\s*=\s*\[\s*["']none""")
HSRS_CONFUSION = re.compile(
    r"""(?i)verify\s*[:=]\s*false\s*[,}]\s*algorithms\s*:\s*\[\s*['"](?:HS|RS)\w*"""
    r"""|verify\s*=\s*False\s*,\s*options\s*=\s*\{[^}]{0,200}?algorithms\s*=\s*\[\s*['"](?:HS|RS)\w*"""
    r"""|algorithms\s*[:=]\s*\[\s*['"]none['"]\s*\]""")
FALLBACK_SECRET = re.compile(
    r"""(?i)\b(auth_?secret|jwt_?secret|secret_?key|signing_?key|api_?key)\b"""
    r"""\s*(?:\?\?|\|\||:=)\s*["'][^"'$]{8,}["']"""
    r"""|["'](?:auth_?secret|jwt_?secret|secret_?key)["']\s*:\s*["'][^"'$]{8,}["']"""
    r"""\s*(?:\?\?|\|\|)""")
LOCALSTORAGE_TOKEN = re.compile(
    r"""(?i)(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*["'][^"']*"""
    r"""(?:token|jwt|auth|session|secret|credential)[^"']*["']""")


def check_config(root, findings):
    for path, text in core.iter_files(root):
        if path.suffix.lower() not in CODE_EXT | CONF_EXT:
            continue
        rel = core.rel_of(path, root)
        if rel.endswith(".md") or core.SECRET_SOFT_FILE.search(rel):
            continue
        for pid, sev, title, rx, fix in CONFIG_CHECKS:
            for m in rx.finditer(text):
                if core.is_comment_or_pattern(text, m.start()) or \
                        core.in_multiline_string(text, m.start()):
                    continue
                findings.append({
                    "id": pid, "severity": sev, "title": title,
                    "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                    "detail": "", "fix": fix,
                })


def check_tls(root, findings):
    for path, text in core.iter_files(root):
        if path.suffix.lower() not in CODE_EXT | CONF_EXT:
            continue
        rel = core.rel_of(path, root)
        if core.SECRET_SOFT_FILE.search(rel):
            continue
        for pid, rx in TLS_CHECKS:
            for m in rx.finditer(text):
                if core.is_comment_or_pattern(text, m.start()):
                    continue
                findings.append({
                    "id": pid, "severity": "critical",
                    "title": "Отключена проверка TLS-сертификата",
                    "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                    "detail": "соединение можно перехватить и подменить, а токены утекут",
                    "fix": "Убери отключение проверки. Для приватного CA укажи его путь, "
                           "но не отключай проверку целиком.",
                })


def check_auth_crypto(root, findings):
    for path, text in core.iter_files(root):
        if path.suffix.lower() not in CODE_EXT:
            continue
        rel = core.rel_of(path, root)
        if core.SECRET_SOFT_FILE.search(rel):
            continue

        def add(pid, sev, title, pos, detail, fix):
            findings.append({
                "id": pid, "severity": sev, "title": title,
                "where": "{}:{}".format(rel, core.line_of(text, pos)),
                "detail": detail, "fix": fix,
            })

        for m in MATH_RANDOM_SECRET.finditer(text):
            if core.is_comment_or_pattern(text, m.start()):
                continue
            add("code.math_random_secret", "warning", "Math.random() для генерации секрета",
                m.start(), "Math.random() не криптографический — значение предсказуемо",
                "Используй crypto.randomUUID() или crypto.getRandomValues().")
        for m in HASH_FOR_PASSWORD.finditer(text):
            add("code.weak_hash_password", "warning", "md5/sha1 для паролей",
                m.start(), "эти хеши не подходят для хранения паролей",
                "Используй bcrypt/argon2/scrypt с солью (bcrypt rounds >= 10).")
        for m in BCRYPT_WEAK.finditer(text):
            add("code.bcrypt_low_rounds", "info", "На проверку: bcrypt с малым числом раундов",
                m.start(), "стоимость подбора низкая, если это не тестовая фикстура",
                "Подними rounds до 10-12 (или переходи на argon2).")
        for m in JWT_DECODE.finditer(text):
            if core.is_comment_or_pattern(text, m.start()):
                continue
            window = text[max(0, m.start() - 400): m.end() + 400]
            if re.search(r"(?i)(algorithms|verify_signature|verify\s*[:=]|jwt\.verify|decode_complete|"
                         r"""options\s*=\s*\{[^}]{0,120}(?:verify|algorithms))""", window):
                continue
            add("code.jwt_decode_no_verify", "warning", "jwt.decode() без параметров проверки",
                m.start(), "рядом не видно проверки подписи и явного списка алгоритмов",
                "Передай verify=True и явный algorithms: [...] — иначе подпись не проверяется.")
        for m in ALG_NONE.finditer(text):
            if core.is_comment_or_pattern(text, m.start()):
                continue
            add("code.jwt_alg_none", "critical", "JWT принимается с alg:none",
                m.start(), "подпись не проверяется — токен подделывается тривиально",
                "Никогда не принимай alg:none — подпись обязана проверяться.")
        for m in HSRS_CONFUSION.finditer(text):
            add("code.jwt_alg_confusion", "warning",
                "На проверку: проверка подписи JWT с отключённым verify",
                m.start(), "verify=false рядом с алгоритмом HS/RS — известный вектор подмены",
                "Явно перечисли algorithms и не отключай verify для HS256/RS256.")
        for m in FALLBACK_SECRET.finditer(text):
            add("code.hardcoded_fallback_secret", "warning", "Захардкоженный запасной секрет",
                m.start(), "если переменная окружения не задана, приложение подпишет токены "
                           "известным ключом",
                "Пусть приложение падает при старте без секрета, а не подставляет дефолт.")
        for m in LOCALSTORAGE_TOKEN.finditer(text):
            add("code.token_in_localstorage", "warning", "Токен авторизации в localStorage",
                m.start(), "localStorage читается скриптом на любой странице — XSS крадёт сессию",
                "Храни сессию в httpOnly-cookie и добавь CSRF-защиту.")


# --- инъекции ------------------------------------------------------------

SHELL_INJECTION = (
    "code.shell_exec_interpolated",
    re.compile(
        r"""(?i)\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*(?:f["']|["'`][^"'`]*["'`]\s*\+|"""
        r"""`[^`]*\$\{|["'][^"']*["']\s*\+\s*\w|template)"""),
)
PICKLE_LOADS = re.compile(r"\b(?:pickle|cPickle|dill)\.loads?\s*\(|\b_pickle\.Unpickler\b")
YAML_UNSAFE = re.compile(
    r"(?i)\byaml\.unsafe_load\s*\(|\byaml\.load\s*\((?![^)]*[Ss]afe)"
    r"""|Loader\s*=\s*yaml\.(?:Unsafe)?Loader\b""")
EXTRACTALL = re.compile(r"\bextractall\s*\(")
EXTRACTALL_SAFE_HINT = re.compile(
    r"(?i)(member\.startswith|validate|safe_extract|check_path|sanitize|\.resolve\(\))")
JINJA_RT_STRING = re.compile(r"render_template_string\s*\(")
MONGO_OPERATOR = re.compile(r"(?i)[\"']?\$(?:gt|gte|lt|lte|ne|regex|where)[\"']?\s*:")
MONGO_CONTEXT = re.compile(r"(?i)\b(?:find|findOne|find_one|aggregate|updateOne|update_one|"
                           r"updateMany|deleteOne|delete_one|remove|findAndModify)\s*\(")
XSS_HTML = re.compile(r"dangerouslySetInnerHTML|v-html\s*=|\binnerHTML\s*=|document\.write\(")
USER_INPUT = re.compile(r"""(?i)(req\.(?:body|query|params)|request\.(?:args|json|form|values)|"""
                        r"""params\[|req\.get\s*\(|query\[|searchParams|getParameter)""")


def check_injection(root, findings):
    for path, text in core.iter_files(root):
        if path.suffix.lower() not in CODE_EXT:
            continue
        rel = core.rel_of(path, root)
        if core.SECRET_SOFT_FILE.search(rel):
            continue

        def add(pid, sev, title, pos, detail, fix):
            findings.append({
                "id": pid, "severity": sev, "title": title,
                "where": "{}:{}".format(rel, core.line_of(text, pos)),
                "detail": detail, "fix": fix,
            })

        pid, rx = SHELL_INJECTION
        for m in rx.finditer(text):
            if core.is_comment_or_pattern(text, m.start()):
                continue
            add(pid, "critical", "Команда ОС собирается из переменных",
                m.start(), "exec/execSync с подстановкой выполняет то, что подставили",
                "Не собирай команду строками: передавай аргументы списком и избегай shell=True.")
        for m in PICKLE_LOADS.finditer(text):
            if core.is_comment_or_pattern(text, m.start()):
                continue
            add("code.pickle_loads", "critical", "pickle.loads на данных извне",
                m.start(), "pickle при десериализации исполняет код",
                "Бери JSON или подписывай данные перед загрузкой.")
        for m in YAML_UNSAFE.finditer(text):
            if core.is_comment_or_pattern(text, m.start()):
                continue
            add("code.yaml_unsafe_load", "critical", "yaml.load без SafeLoader",
                m.start(), "небезопасный загрузчик YAML исполняет конструкторы объектов",
                "Используй yaml.safe_load.")
        for m in EXTRACTALL.finditer(text):
            if core.is_comment_or_pattern(text, m.start()):
                continue
            window = text[max(0, m.start() - 300): m.end() + 200]
            has_check = bool(EXTRACTALL_SAFE_HINT.search(window))
            add("code.zip_slip",
                "info" if has_check else "warning",
                "На проверку: распаковка архива без проверки путей (zip-slip)",
                m.start(),
                "запись с «../» может выйти за пределы каталога распаковки"
                if not has_check else
                "проверка путей рядом не читается — убедись вручную",
                "Проверь, что путь внутри архива не выходит за пределы целевого каталога.")
        for m in JINJA_RT_STRING.finditer(text):
            if core.is_comment_or_pattern(text, m.start()):
                continue
            add("code.jinja_render_string", "critical", "render_template_string",
                m.start(), "шаблон собирается из строки — возможен SSTI",
                "Рендери только шаблоны из файлов, ввод передавай как контекст.")
        for m in MONGO_OPERATOR.finditer(text):
            window = text[max(0, m.start() - 400): m.end() + 200]
            if not (MONGO_CONTEXT.search(window) or USER_INPUT.search(window)):
                continue
            add("code.mongo_operator_injection", "warning",
                "На проверку: Mongo-запрос с оператором в фильтре",
                m.start(), "$gt и подобные в данных запроса — это NoSQL-инъекция",
                "Приводи значения к ожидаемым типам и не собирай фильтр из тела запроса.")
        for m in XSS_HTML.finditer(text):
            if core.is_comment_or_pattern(text, m.start()):
                continue
            window = text[max(0, m.start() - 300): m.end() + 400]
            if not USER_INPUT.search(window):
                continue
            add("code.xss_inner_html", "warning",
                "На проверку: опасная вставка HTML рядом с пользовательским вводом",
                m.start(), "значение может прийти от пользователя — это XSS",
                "Экранируй вывод или рендери без innerHTML.")


# --- SSRF ----------------------------------------------------------------

FETCH_CALL = re.compile(
    r"""(?i)\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete))?|requests\.(?:get|post|put|head)|"""
    r"""httpx\.(?:get|post)|urlopen|http\.request|got|nodeFetch)\s*\(\s*""")
URL_TEMPLATE = re.compile(r"""[`"']?[a-z][a-z0-9+.-]*://[^"'`\s]{0,40}?\$\{|"""
                           r"""(?:["'`]\s*\+\s*\w|[a-z_]\w*\s*\+\s*["'`]https?://)""")


def check_ssrf(root, findings):
    for path, text in core.iter_files(root):
        if path.suffix.lower() not in CODE_EXT:
            continue
        rel = core.rel_of(path, root)
        if core.SECRET_SOFT_FILE.search(rel):
            continue
        for m in FETCH_CALL.finditer(text):
            if core.is_comment_or_pattern(text, m.start()):
                continue
            window = text[m.start(): m.start() + 400]
            if not URL_TEMPLATE.search(window):
                continue
            around = text[max(0, m.start() - 300): m.start()] + window
            if not USER_INPUT.search(around):
                continue
            findings.append({
                "id": "code.ssrf", "severity": "warning",
                "title": "На проверку: URL для запроса собран из пользовательского ввода",
                "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                "detail": "если адрес не ограничен списком доменов, запрос уходит туда, куда "
                          "укажет клиент, включая внутреннюю сеть",
                "fix": "Валидируй URL по белому списку хостов и запрети внутренние адреса.",
            })


# --- framework config ----------------------------------------------------

DJANGO_CHECKS = [
    ("code.django_allowed_hosts", re.compile(r"""ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']"""),
     "ALLOWED_HOSTS = ['*'] принимает любой Host-заголовок.",
     "Перечисли свои домены: ALLOWED_HOSTS = ['example.com']."),
    ("code.django_cors_all", re.compile(r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True"),
     "любой сайт может делать кросс-доменные запросы с твоими куками",
     "Замени на CORS_ALLOWED_ORIGINS со списком своих доменов."),
    ("code.django_cookie_insecure", re.compile(r"SESSION_COOKIE_SECURE\s*=\s*False|"
                                               r"CSRF_COOKIE_SECURE\s*=\s*False"),
     "сессионная/csrf-cookie уходит и по http — её можно перехватить в сети",
     "Поставь *_COOKIE_SECURE = True (за HTTPS) и SESSION_COOKIE_HTTPONLY = True."),
]
RAILS_SSL_OFF = re.compile(r"(?i)force_ssl\s+false|config\.force_ssl\s*=\s*false")
SKILLIT_PUBLIC = re.compile(r"""\$env/static/public|/static/public/""")
ASTRO_PUBLIC = re.compile(r"""import\.meta\.env\.[A-Z0-9_]+""")
ASTRO_SECRETISH = re.compile(r"(?i)(SECRET|TOKEN|API_KEY|PASSWORD|PRIVATE)")
EXPO_PUBLIC = re.compile(r"""\bEXPO_PUBLIC_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)""")


def check_framework_config(root, findings):
    for path, text in core.iter_files(root):
        suf = path.suffix.lower()
        rel = core.rel_of(path, root)
        if core.SECRET_SOFT_FILE.search(rel):
            continue
        if suf == ".py":
            for pid, rx, detail, fix in DJANGO_CHECKS:
                for m in rx.finditer(text):
                    if core.is_comment_or_pattern(text, m.start()) or \
                            core.in_multiline_string(text, m.start()):
                        continue
                    findings.append({
                        "id": pid, "severity": "warning", "title": "Django: небезопасная настройка",
                        "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                        "detail": detail, "fix": fix,
                    })
        if suf == ".rb":
            for m in RAILS_SSL_OFF.finditer(text):
                findings.append({
                    "id": "code.rails_force_ssl_off", "severity": "warning",
                    "title": "Rails: force_ssl отключён",
                    "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                    "detail": "session cookie уходит по http",
                    "fix": "Включи config.force_ssl = true (config/environments/production.rb).",
                })
        if suf in {".js", ".ts", ".svelte", ".astro", ".mjs", ".cjs"}:
            for m in SKILLIT_PUBLIC.finditer(text):
                findings.append({
                    "id": "code.static_public", "severity": "warning",
                    "title": "SvelteKit: файл в static/public попадёт в сборку",
                    "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                    "detail": "всё, что лежит в static/public, отдаётся как есть",
                    "fix": "Не клади секреты в static/public; приватные данные держи на сервере.",
                })
            for m in ASTRO_PUBLIC.finditer(text):
                if core.is_comment_or_pattern(text, m.start()) or \
                        core.in_multiline_string(text, m.start()):
                    continue
                window = text[max(0, m.start() - 40): m.end() + 20]
                if not ASTRO_SECRETISH.search(window):
                    continue
                findings.append({
                    "id": "code.astro_public_env", "severity": "warning",
                    "title": "На проверку: Astro import.meta.env с именем похожим на секрет",
                    "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                    "detail": "в Astro в клиент уходит только PUBLIC_-префикс, но имя выглядит "
                              "как секретное",
                    "fix": "Секреты читай через server-only переменную окружения (без PUBLIC_).",
                })
        if suf in {".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"}:
            for m in EXPO_PUBLIC.finditer(text):
                if core.is_comment_or_pattern(text, m.start()):
                    continue
                findings.append({
                    "id": "code.expo_public_secret", "severity": "warning",
                    "title": "EXPO_PUBLIC_ с именем похожим на секрет",
                    "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                    "detail": "EXPO_PUBLIC_* попадает в клиентский бандл Expo",
                    "fix": "Держи секреты без EXPO_PUBLIC_ и вызывай API со своего бэкенда.",
                })


# --- авторизация ---------------------------------------------------------

ROLE_FROM_CLIENT = re.compile(
    r"(?i)(req\.body\.role|body\.role|request\.json\(\)\s*\[\s*['\"]role|data\.role|params\.role)")
ID_FROM_REQUEST = re.compile(r"(?i)(req\.(?:query|params)\.(?:id|user_?id|account)|params\.get\(['\"]id)")
OWNER_CHECK = re.compile(
    r"(?i)(owner|belongs|user_?id\s*==|\.eq\(\s*['\"]?user|current_?user|tenant_id|auth\.user)")
JWT_NO_EXP = re.compile(r"ignoreExpiration\s*:\s*true|verify_exp\s*[:=]\s*False", re.I)


def check_authz(root, findings):
    """Эвристики по правам доступа — помечаем «на проверку»."""
    for path, text in core.iter_files(root):
        if path.suffix.lower() not in CODE_EXT:
            continue
        rel = core.rel_of(path, root)
        if core.SECRET_SOFT_FILE.search(rel):
            continue
        for m in ROLE_FROM_CLIENT.finditer(text):
            if core.is_comment_or_pattern(text, m.start()):
                continue
            findings.append({
                "id": "code.role_from_client", "severity": "warning",
                "title": "Роль берётся из запроса клиента",
                "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                "detail": "клиент может прислать role: admin",
                "fix": "Роль читай из проверенной сессии/токена на сервере, не из тела запроса.",
            })
        idm = ID_FROM_REQUEST.search(text)
        if idm and not OWNER_CHECK.search(text):
            findings.append({
                "id": "code.idor_suspect", "severity": "info",
                "title": "На проверку: доступ к ресурсу по id из запроса",
                "where": "{}:{}".format(rel, core.line_of(text, idm.start())),
                "detail": "не видно проверки, что ресурс принадлежит текущему пользователю "
                          "(возможен IDOR)",
                "fix": "Фильтруй запрос по владельцу: WHERE user_id = current_user, "
                       "а не только по присланному id.",
            })
        for m in JWT_NO_EXP.finditer(text):
            if core.is_comment_or_pattern(text, m.start()):
                continue
            findings.append({
                "id": "code.jwt_no_exp", "severity": "warning",
                "title": "JWT принимается без проверки срока",
                "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                "detail": "срок действия токена игнорируется — украденный токен живёт вечно",
                "fix": "Не отключай проверку exp.",
            })


# --- rate limit и AI-расходы ---------------------------------------------

RL_IMPORT = re.compile(
    r"""(?im)^\s*(?:import\b[^\n]*?\bfrom\s*|import\s+|const\s+\w+\s*=\s*require\(\s*|from\s+)"""
    r"""['"]?(?:express-rate-limit|express-slow-down|@upstash/ratelimit|rate-limiter-flexible|"""
    r"""@nestjs/throttler|slowapi|django_ratelimit|django-ratelimit|flask_limiter|limits|"""
    r"""@fastify/rate-limit|fastify-rate-limit|koa-ratelimit|hono/rate-limit|next-rate-limit|"""
    r"""bottleneck)""")
SENSITIVE_ROUTE = re.compile(
    r"""(?i)['"`/](login|signin|sign-in|signup|sign-up|register|reset-password|forgot|verify|otp)"""
    r"""['"`/]""")
AI_CALL = re.compile(r"(?i)(\.chat\.completions|\.messages\.create|generateContent|"
                     r"google\.generativelanguage|api\.groq\.com|\.completions\.create)")
AI_PROVIDER_WORD = re.compile(r"(?i)\b(openai|anthropic|groq)\b")
IMPORT_LINE = re.compile(r"(?i)^\s*(?:import\b|from\b|const\s+\w+\s*=\s*require\(|#|//)")
AI_ROUTE = re.compile(r"(?i)(app\.(?:post|get)|router\.(?:post|get)|@(?:app|router)\.(?:post|get)|"
                      r"""\.(?:route|get|post)\(\s*["'`/]|export\s+(?:async\s+)?function\s+handler)""")
AI_WINDOW = 300
TOKEN_LIMIT_RE = re.compile(r"(?i)(max_tokens|max_completion_tokens|max_output_tokens|maxTokens|"
                            r"""["']maxOutputTokens["']\s*:)""")
AUTH_HINT = re.compile(
    r"""(?i)auth|verifyToken|verify_token|requireUser|require_user|getSession|get_session"""
    r"""|middleware|authorize|jwt|passport|session|protect\(|require\(['"][^'"]*(?:auth|user)""")


def _is_import_line(text, pos):
    """Находится ли позиция на строке импорта/require — упоминание SDK не считается вызовом."""
    start = text.rfind("\n", 0, pos) + 1
    return bool(IMPORT_LINE.match(text[start:start + 200]))


def check_rate_limit_and_ai(root, findings):
    files = {}
    for path, text in core.iter_files(root):
        if path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py"}:
            files[core.rel_of(path, root)] = text
    if not files:
        return

    has_ratelimit = any(RL_IMPORT.search(t) for t in files.values())
    if not has_ratelimit:
        for rel, text in files.items():
            m = next((mm for mm in SENSITIVE_ROUTE.finditer(text)
                      if not core.is_comment_or_pattern(text, mm.start())), None)
            if not m:
                continue
            findings.append({
                "id": "code.no_ratelimit_auth", "severity": "warning",
                "title": "Auth-роут без rate limit",
                "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                "detail": "в проекте не найдено ни одной библиотеки rate-limiting",
                "fix": "Добавь лимит на login/signup/reset (express-rate-limit, slowapi, "
                       "@upstash/ratelimit). Иначе — брутфорс и спам кодов.",
            })
            break

    for rel, text in files.items():
        calls = [m for m in AI_CALL.finditer(text)
                 if not core.is_comment_or_pattern(text, m.start())]
        if not calls:
            # провайдер упомянут, но явного вызова нет — смотрим только на строки кода
            calls = [m for m in AI_PROVIDER_WORD.finditer(text)
                     if not core.is_comment_or_pattern(text, m.start())
                     and not _is_import_line(text, m.start())]
        for m in calls:
            window = text[max(0, m.start() - AI_WINDOW): m.end() + AI_WINDOW]
            if TOKEN_LIMIT_RE.search(window):
                break
            findings.append({
                "id": "code.ai_no_maxtokens", "severity": "warning",
                "title": "Вызов LLM без лимита длины ответа",
                "where": "{}:{}".format(rel, core.line_of(text, m.start())),
                "detail": "запрос к платному AI-API без max_tokens/max_output_tokens",
                "fix": "Задай max_tokens (OpenAI), max_completion_tokens или maxOutputTokens "
                       "(Gemini) и лимит длины входа.",
            })
            break

    # LLM-эндпоинт: в v1 это был critical по отсутствию «ключевого слова авторизации».
    # Точность по ключевым словам низкая, поэтому warning с честной формулировкой.
    for rel, text in files.items():
        if not (AI_CALL.search(text) and AI_ROUTE.search(text)):
            continue
        if AUTH_HINT.search(text):
            continue
        findings.append({
            "id": "code.ai_open_endpoint", "severity": "warning",
            "title": "На проверку: LLM-вызов в роуте, авторизация не видна",
            "where": rel,
            "detail": "файл вызывает платный LLM и содержит роут; проверки прав в этом же файле "
                      "не найдено. Возможно, но не доказано: авторизация может быть в middleware "
                      "или в импортированном модуле",
            "fix": "Проверь, что эндпоинт закрыт авторизацией и лимитом запросов на пользователя.",
        })
        break
