# NOTICE — attribution and provenance

This repository is a **v2.0 rework** of the `vibe-audit` skill. It is built on
someone else's MIT-licensed work, and the license requires the original
copyright to be preserved.

| | |
|---|---|
| Original work | `vibe-audit` — Copyright (c) 2026 **ika.explains** |
| Upstream host | <https://github.com/haraldalder-vibemogger/vibe-audit> (MIT) |
| This repository | github.com/Samiixo/vibecode-audit |
| Upstream license | MIT — see `LICENSE`, copyright line **unchanged** |

**Do not remove the original copyright line from `LICENSE` and do not relicense
the upstream code under different terms.** Attribution here is a requirement of
the license, not a courtesy. If you fork this, keep this file.

## What v2.0 changed

Upstream content is credited to ika.explains. Changes made here:

### Fixed (defects reproduced first, then fixed)

- **Console crash.** Emoji output (`🩺🔴🟡🔵🌐`) raised `UnicodeEncodeError` on a
  cp1251/cp866 console — the default on a Russian Windows install. Both scripts.
- **Dependency audit never ran on Windows** — `--userconfig /dev/null` is a POSIX
  path and `npm` is `npm.cmd` there, so the check silently degraded to an info
  note.
- **Locale decoding of subprocess output** broke on non-ASCII (Cyrillic) file
  names coming from `git ls-files`.
- **Invisible file types.** `Dockerfile`, `*.tf`, `*.tfvars`, `.npmrc`, `.netrc`,
  `.pypirc`, `Makefile`, `Procfile`, `*.pem`/`*.key` and friends were never
  scanned at all — precisely where infrastructure secrets live.
- **Silent skips.** Files over 1 MB vanished from the report while the report
  implied full coverage.
- **Non-interactive `livecheck`.** `input()` raised `EOFError` in an agent or CI
  shell instead of failing cleanly.
- **Misleading headline.** A run whose findings were all `info` ("на проверку")
  still exited 1 and counted them as "находок".
- **Stale user agent** pointing at the old upstream repository.

### Added

- **No `PYTHONIOENCODING` blind spot.** The self-test runs a pass on a `cp1251`
  console on purpose: forcing UTF-8 for every child process is what let the
  console crash ship unnoticed in v1.
- **No secret-shaped literals in git.** Fixture secrets are generated at run
  time; the repository holds `__FAKE_*__` placeholders. GitHub push protection
  blocks pushes containing strings shaped like live keys, and a fake-but-real
  key in history is bad practice regardless.
- **Machine-readable output**: `--json` for both scripts, documented shape, so
  the tool can gate CI or feed an agent.
- **A self-test**: `tests/run_selftest.py` with a deliberately broken fixture, a
  realistically clean fixture, and hostile inputs. No network, no npm.

### Detection expansion (the "modern realities" part)

v1 knew about hardcoded keys, CORS `*`, `debug=True`, `eval(`, SQL via f-string,
`alg:none`, `.env` in git, open AI endpoints and firebase rules. v2 adds:

- modern key providers (OpenAI project keys, Google, GitHub fine-grained,
  GitLab, npm, PyPI, SendGrid, Twilio, Slack/Discord webhooks, Cloudflare, Vercel,
  Supabase `sb_secret_`, HuggingFace, Replicate, Groq, OpenRouter, Azure
  connection strings, JWT literals);
- **TLS verification switched off** (`verify=False`, `rejectUnauthorized: false`,
  `NODE_TLS_REJECT_UNAUTHORIZED=0`, …) — a silent MITM hole;
- **CI/CD as an attack surface**: `pull_request_target` + checkout of the PR ref,
  secrets echoed in `run:`, `permissions: write-all`, self-hosted runners on
  public repos, unpinned actions;
- **Docker/Terraform**: `privileged: true`, root containers, `curl | bash`,
  `ADD <url>`, `:latest`, `chmod 777`, secrets in `ENV`/`ARG`/`--build-arg`;
- **auth & crypto misuse**: `Math.random()` for tokens, md5/sha1 passwords, low
  bcrypt rounds, `jwt.decode` used as verification, algorithm confusion, hardcoded
  `AUTH_SECRET` fallbacks, auth tokens in `localStorage`;
- **injection beyond SQL**: command execution with interpolation, `os.system`,
  `pickle.loads`, unsafe `yaml.load`, zip-slip, SSTI, NoSQL `$where`,
  `dangerouslySetInnerHTML` with user input;
- **SSRF** via a fetch whose URL comes from request input;
- **framework config**: Django `ALLOWED_HOSTS=['*']`, `CORS_ALLOW_ALL_ORIGINS`,
  Rails `force_ssl false`, Astro/SvelteKit/Expo public env prefixes;
- **supply chain**: `postinstall` scripts, `curl|bash` in npm scripts, missing
  lockfile, git-URL dependencies;
- **MCP / agent config** with literal secrets in an `env` block;
- **AI spend safety**: `max_output_tokens` and `max_completion_tokens` alongside
  `max_tokens`;
- **`livecheck`**: `SameSite`, `Referrer-Policy`, `Permissions-Policy`, HSTS
  `max-age`, Spring actuator, Swagger/OpenAPI, `.env.*` variants, dumps,
  `.svn`, and a positive check for `/.well-known/security.txt`.

### What was NOT changed

- The finding schema (`id` / `severity` / `title` / `where` / `detail` / `fix`),
  the Russian report format, the headline number, and the severity vocabulary.
- The defensive framing: no exploit payloads, no advice on attacking anything,
  live checks only against a domain the user confirmed they own.
- `references/checklist.md` — the human checklist stays a separate, hand-run
  document. It was extended, not rewritten.
