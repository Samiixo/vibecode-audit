# Changelog

All notable changes to this skill. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/spec/v2.0.0.html).

Upstream work is credited to ika.explains (`vibe-audit`, MIT — see
[NOTICE.md](NOTICE.md)). Everything below is what changed here.

## [2.0.0] — 2026-10-02

A rework, not a patch. The scanner was split into modules, every defect below was
reproduced before being fixed, and the detection set was extended to the modern
attack surface: CI/CD, containers, Terraform, MCP configs, TLS, and AI spend.

### Fixed

- **Console crash on Windows.** Emoji output raised `UnicodeEncodeError` on a
  cp1251/cp866 console — the default on a Russian Windows install. Both scripts.
- **The dependency audit never ran on Windows.** `--userconfig /dev/null` is a
  POSIX path and the binary is `npm.cmd`, so `npm audit` silently degraded to an
  info note on every Windows machine.
- **Locale decoding of subprocess output** mangled non-ASCII (Cyrillic) file
  names coming from `git ls-files`.
- **Invisible file types.** `Dockerfile`, `*.tf`, `*.tfvars`, `.npmrc`, `.netrc`,
  `.pypirc`, `Makefile`, `Procfile`, `*.pem`, `*.key`, `*.mjs/.cjs/.mts/.cts`,
  `.astro` were never opened — a secret in a Dockerfile `ARG` or an `.npmrc`
  `_authToken` had no way to be found.
- **Silent skips.** Files over the size cap disappeared from the report while the
  report implied full coverage. Skips are now listed in the report and in the
  console line.
- **The scanner flagged its own pattern definitions.** Running it inside a repo
  that contains the skill produced eight false warnings. It now skips its own
  install directory — compared by real path, not by folder name, so it works no
  matter what the repo is called — and says that it did so. The self-skip is a
  single `skip_path()` helper used by every check: the CI/CD, container,
  Terraform and MCP checks used their own `rglob` and were bypassing it, which
  made the skip half-working and surfaced the deliberately broken test fixtures
  as real findings.
- **`livecheck` header lookup never matched.** Header names were compared
  case-sensitively, and servers send `Content-type` — so a missing `Content-Type`
  check could never fire. Keys are now lowercased.
- **`livecheck` could hang** on a dead host; every request now carries a timeout
  and the run has a total-time guard, so an unreachable site is an error with a
  valid JSON payload instead of a hang.
- **A wrong exit code.** A non-existent path exited 1, which is documented as
  "at least one warning", so a broken invocation read as a security finding in
  CI. Invalid path and internal errors now exit 2.
- **Quadratic scanning.** `line_of` and the comment guard rescanned the file per
  match: a 900 KB minified file took 6.4 s and flooded the report. Line lookup is
  now O(1) via cached newline offsets, findings are capped per rule per file, and
  the same scan takes 0.9 s.
- **Non-interactive `livecheck`.** `input()` raised `EOFError` in an agent or CI
  shell. It now fails cleanly with a message and a documented exit code.
- **Stale user agent** in `livecheck.py` pointing at the old upstream repository.

### Added

- **41 rule ids across the new categories**, roughly:
  - 20 new secret providers (OpenAI project keys, Google, GitHub fine-grained,
    GitLab, npm, PyPI, SendGrid, Twilio, Slack/Discord webhooks, Cloudflare,
    Vercel, Supabase `sb_secret_`, HuggingFace, Replicate, Groq, OpenRouter,
    Azure connection strings, bare JWT literals) plus `.npmrc` tokens, `.netrc` /
    `.pypirc` credentials and `Dockerfile ARG` leaks.
  - **TLS verification disabled** in six forms.
  - **GitHub Actions** as an attack surface: `pull_request_target` + checkout of a
    PR ref, secrets echoed in `run:`, `permissions: write-all`, self-hosted
    runners on public repos, unpinned actions.
  - **Docker / Terraform**: `privileged: true`, host networking, root containers,
    `curl | bash`, `ADD <url>`, `:latest`, `chmod 777`, secrets in `ENV`/`ARG`,
    published DB ports, literal secrets in `*.tfvars`.
  - **Auth and crypto misuse**: `Math.random()` tokens/OTP, md5/sha1 passwords,
    low bcrypt rounds, `jwt.decode` used as verification, `alg:none`, HS/RS
    confusion, hardcoded `AUTH_SECRET` fallbacks, tokens in `localStorage`.
  - **Injection beyond SQL**: command execution with interpolation, `pickle`,
    unsafe `yaml.load`, zip-slip, Jinja `render_template_string`, Mongo `$where`,
    `dangerouslySetInnerHTML` with user input.
  - **SSRF** from request input; Django/Rails/Astro/SvelteKit/Expo config;
    supply chain (`postinstall`, `curl|sh`, git-URL dependencies, missing
    lockfile); MCP and agent configs with literal secrets; AI spend extended to
    `max_completion_tokens` and `max_output_tokens`.
- **`--json` on both scripts**, with a documented payload that is valid on every
  path including an internal checker error — usable from CI and from an agent.
- **`livecheck.py`** rewritten: `--json`, `--timeout`, `--paths` (replaces the
  default probe list) and a hard cap of 40 requests so a custom list cannot turn
  it into a scan; `SameSite` added to the cookie check; `Referrer-Policy` and
  `Permissions-Policy` added to the header list; HSTS with a `max-age` under
  180 days is now a warning; leak paths extended with Spring actuator, Swagger/
  OpenAPI, `.env.*` variants, dumps, `.svn` and `config/config.json`; plus a
  **positive** check for `/.well-known/security.txt`, whose absence is `info` and
  never a failure.
- **A self-test** — `tests/run_selftest.py`, **28 checks in ~6 s**, no network
  beyond localhost and no npm: a deliberately broken fixture, a realistically
  clean fixture that must produce zero `critical` and zero `warning`, hostile
  inputs (empty dir, missing path, 5 MB minified file, binary, cp1251-encoded and
  Cyrillic-named files, symlink cycle), a `cp1251` console regression for both
  scripts, and a throwaway localhost HTTP server that proves `livecheck` reports
  an exposed `.env` while not false-positiving on an SPA catch-all route.

### Changed

- `scripts/audit.py` is now an orchestrator over three check modules
  (`checks_secrets.py`, `checks_infra.py`, `checks_code.py`) instead of one large
  file.
- **Severity discipline tightened.** Only unambiguous, high-confidence problems
  are `critical`. The old `ai_open_endpoint` heuristic — which fired `critical`
  whenever a file mentioned an AI call and any route keyword while lacking a
  coarse auth keyword somewhere in the file — is now `warning` with explicit
  "needs a human look" wording, because that heuristic cannot be made precise.
- Public env prefixes extended beyond `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` to
  Astro `PUBLIC_*`, SvelteKit `$env/static/public` and `EXPO_PUBLIC_*`.
- `references/checklist.md` extended with CI/CD, containers, MCP/agent config and
  an incident-response section.

### Known limits of v2.0

- `--build-arg` secrets and a bare `secret:` in a GitHub Actions `env:` block are
  not `critical` findings: they need value-shape certainty to avoid crying wolf,
  so they are reported at a lower level with context instead.
- Native extensions and non-UTF-16 files are read as UTF-8 with replacement, so
  their content is only partly matched — no crash, but not full coverage.
- Static analysis still cannot prove authorization logic, ownership checks, RLS
  policies, cloud-console rights or anything needing two real accounts. Those stay
  in `references/checklist.md`, where a human has to look.