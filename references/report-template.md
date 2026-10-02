# Report template — `vibe-audit-report.md`

The report is written to the path given by `--report` (default
`vibe-audit-report.md` in the current directory). The structure below is the
canonical one; the tool produces it, and the agent's job in chat is to summarise,
not to restate it.

```markdown
# 🩺 vibe-audit: <имя проекта>

**Итог: N находок — 🔴 X критичных, 🟡 Y важных, 🔵 Z на проверку**

## 🔴 <название находки>
- Где: `путь/файл.js:42`
- Детали: <что не так, маскированное значение если секрет>
- Как чинить: <одна строка, конкретное действие>

## 🟡 <название находки>
- Где: `config/app.py:88`
- Детали: …
- Как чинить: …

## 🔵 <название находки>
- Где: `app/api/orders/route.ts`
- Детали: не видно проверки владельца — проверить руками
- Как чинить: фильтруй выборку по user_id текущей сессии
```

## Rules that are not negotiable

1. **One finding = one block**, sorted by severity: all 🔴 first, then 🟡, then 🔵.
2. **Secrets are masked, always** — `sk-pro…op`, never the full value, in the
   report and in chat. A masked value still identifies the key for rotation.
3. **`critical` means "certainly wrong"**, not "suspicious". A heuristic that
   depends on surrounding code is `warning` or `info` and says «на проверку» in
   its detail. An audit that cries wolf gets deleted by its users.
4. **A skipped check is stated, not hidden.** Files too large to scan, a missing
   `npm`, no git, a check that raised an internal error — each appears in the
   report (severity `info`, id `check_error` / skip note) with the reason.
5. **The headline number is the real tally**, and `info` findings are never
   counted as warnings. Exit codes: `0` nothing above info, `1` at least one
   warning, `2` at least one critical.
6. **No exploit detail.** The fix is the payload-free half of the job. Do not add
   proof-of-concept code, curl commands that exploit something, or "here is how
   an attacker would use it".
7. **Machine-readable output** (`--json`) must parse on every path: all clean,
   some findings, and an internal checker error. Shape:

```json
{
  "tool": "vibe-audit",
  "version": "2.0.0",
  "root": "D:\\path\\to\\project",
  "scanned_at": "2026-10-02T09:00:00",
  "exit_code": 2,
  "totals": { "critical": 1, "warning": 2, "info": 3 },
  "skipped": ["dist/bundle.js — файл больше лимита"],
  "findings": [
    {
      "id": "secrets.stripe_live",
      "severity": "critical",
      "title": "Stripe live key",
      "where": "src/pay.ts:3",
      "detail": "найдено: sk-li…uv",
      "fix": "Перевыпусти ключ, вынеси в переменную окружения."
    }
  ]
}
```
