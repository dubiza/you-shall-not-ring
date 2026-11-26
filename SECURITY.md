# Security Policy

## Supported Versions

Security updates are applied directly to the latest commit on the `main` branch.

| Version / Branch | Supported |
| :--- | :--- |
| `main` | Yes |
| Older commits / forks | No |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussions.**

Instead, please submit a report privately via **GitHub Private Security Advisories**:

* https://github.com/dubiza/you-shall-not-ring/security/advisories/new

When reporting an issue, please include:
* A clear description of the vulnerability and its potential impact (e.g., webhook authentication bypass, JWT validation flaw, stored XSS/injection in the dashboard, or prompt-injection bypass).
* Steps or a minimal test case to reproduce the behavior.
* Any suggested fix or mitigation, if you have one.

We aim to acknowledge reports within 72 hours and provide a fix or mitigation plan as quickly as possible.

## Security Architecture Summary

You Shall Not Ring relies on the following boundary controls:

* **Twilio Webhook Verification:** All `/voice/*` routes verify `X-Twilio-Signature` (`HMAC-SHA1`) using `TWILIO_AUTH_TOKEN` before reading or mutating caller state.
* **Admin API Authentication:** `/admin/*` endpoints authenticate callers with a constant-time comparison against `ADMIN_TOKEN`.
* **Dashboard Zero Trust Access:** `/dashboard` and `/dashboard/api/*` are designed to sit behind path-scoped Cloudflare Zero Trust Access (Email OTP) and additionally perform in-Worker `RS256` JWT validation (`iss`, `aud`, `exp`, `nbf`, cached JWKS), failing closed (`503`) if Access configuration is missing.
* **Privacy-Preserving Contacts Sync:** Device contacts synced via `/admin/contacts-sync` are normalized and stored in Workers KV as salted 128-bit `HMAC-SHA256` digests rather than plaintext phone numbers.
* **AI Prompt-Injection Guard:** Workers AI (`@cf/cloudflare/clef`) evaluates a dedicated `prompt_injection` score alongside caller intent, dropping suspected manipulation attempts.

## Out of Scope

Because this project is self-hosted by each user on their own Cloudflare and Twilio accounts, the following operational misconfigurations are outside the project's vulnerability scope:

* Enabling Worker-wide Cloudflare Access over `/voice/*` or `/admin/*` or loosening your Zero Trust Access email policy.
* Leaking or committing personal `.dev.vars` or `local.config.json` files.
* Carrier call-forwarding rules, Twilio account security, or SIP endpoint credentials.
