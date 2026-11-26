# Contributing to You Shall Not Ring

Thank you for your interest in contributing! Bug reports, hardening improvements, documentation fixes, and clean pull requests are all welcome.

## Local Setup

1. Fork and clone the repository:
   ```zsh
   git clone https://github.com/<your-username>/you-shall-not-ring.git
   cd you-shall-not-ring
   npm install
   ```
2. *(Optional)* Only copy `local.config.example.json` → `local.config.json` and `.dev.vars.example` → `.dev.vars` if you are deploying to your own Cloudflare account. All tests and builds run cleanly on a default checkout without either file.

## Required Checks Before Opening a Pull Request

Every pull request must pass all three checks cleanly with exit code `0`:

```zsh
npm run typecheck   # cf workers types && strict tsc
npm test            # Vitest unit & SQLite-backed integration suite
npm run build       # Production Cloudflare Worker bundle via cf build
```

## Coding & Architecture Standards

* **Strict TypeScript:** Keep `strict: true` and `noUncheckedIndexedAccess: true` happy without `any` casts or type-suppression shortcuts.
* **Cloudflare Tooling:** This project uses the `cf` CLI and `cloudflare.config.ts`—do not introduce Wrangler config files (`wrangler.toml` / `wrangler.jsonc`).
* **Documentation:** Give every public function, class, and exported interface a concise JSDoc comment, and use inline comments to explain *why* non-obvious decisions were made.
* **Error Handling & Security:** Never leave empty `catch` blocks, never weaken webhook/JWT validation, and add unit or integration tests covering any new screening rule, parser, or API endpoint.
* **Privacy First (Critical):** Never commit real phone numbers, personal names, email addresses, Cloudflare team domains, `.dev.vars`, or `local.config.json`. Keep all test fixtures fictional (e.g., `+14155550100`, `owner@example.com`, `firewall.example.com`).

## Reporting Security Issues

Do **not** open a public issue or PR for security vulnerabilities. See [SECURITY.md](SECURITY.md) for private reporting instructions.
