# Per-CVE plugin registry

Each **real** Bitrix (or Bitrix-relevant) CVE lives in its own `cve_*.py` file
here. The RCE tester loads them through `load_plugins()` — drop a new file in
and nothing else needs to change.

## Contract

- Subclass `CVECheck` (see `base.py`) and expose the instance as `PLUGIN`.
- Set metadata: `cve_id`, `title`, `affected`, `severity`, `auth`
  (`unauth` | `authenticated` | `admin`), `disputed`, `references`.
- For a simple reachability probe, set `endpoint` / `method` / `payload` /
  `marker` and let the default `check()` run.
- For a richer (still **non-destructive**) proof, override `check(self,
  requester, base_url)` and return a `CheckResult(detected, confidence,
  evidence, detail)` where `confidence` is `'reachable'` or `'confirmed'`.
- For **local mode** (running on the host), optionally implement
  `local_check(self, host)` where `host` is a `utils.localhost.LocalHost`.
  Resolve the exact installed package/module version and return a `CheckResult`
  with confidence `'confirmed'` (vulnerable) or `'not_affected'` (patched).

## Rules of the house

- **Non-destructive only.** Plugins probe/fingerprint; they must not upload
  shells, write files, or run commands. Full exploitation belongs in a
  dedicated aggressive routine, not the registry sweep.
- **Reachability ≠ exploited.** The tester caps `'reachable'` findings at
  severity `high`; only `'confirmed'` keeps the plugin's own severity.
- **Cite sources.** Every plugin lists authoritative `references` (NVD, vendor
  advisory, credible research). Mark any guessed endpoint `# unverified path`.

## Current plugins

| CVE | Layer | Auth | Notes |
|-----|-------|------|-------|
| CVE-2022-27228 | Bitrix vote module | unauth | Corrected endpoint `/bitrix/tools/vote/uf.php` |
| CVE-2023-1713  | Bitrix24 | auth | Insecure temp-file (Instagram import) |
| CVE-2023-1714  | Bitrix24 | auth | Unsafe variable extraction |
| CVE-2023-1719  | Bitrix24 | auth¹ | IDOR + reflected XSS -> PHP RCE |
| BITRIX-html_editor_action | Site Manager | unauth | Object-injection RCE (webshell upload); no CVE |
| CVE-2025-67886 | Bitrix24 | auth | Translate module; vendor-disputed; path unverified |
| CVE-2025-67887 | 1C-Bitrix | auth | Translate module; vendor-disputed; path unverified |
| CVE-2026-42945 | nginx (bx-nginx) | unauth | "NGINX Rift"; advisory only -- server_tokens/backports make remote version unreliable, verify on host |

¹ IDOR surface is unauthenticated; the XSS->RCE path fires in an admin session.
