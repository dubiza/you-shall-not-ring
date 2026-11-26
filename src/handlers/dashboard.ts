import { verifyCloudflareAccessRequest } from "../security/cloudflareAccess.ts";
import { normalizePhoneNumber } from "../security/crypto.ts";
import { getDashboardSummary, listCallLogs } from "../storage/callLogs.ts";
import {
	deleteCallerRecord,
	getContactsSnapshotMeta,
	setCallerRecord,
} from "../storage/callerList.ts";
import {
	deleteCallerRule,
	exportCallerRulesCsv,
	importCallerRulesCsv,
	listCallerRules,
	upsertCallerRule,
} from "../storage/callerRules.ts";
import type {
	CallerRuleStatus,
	CsvImportMode,
	DashboardPeriod,
	CallFirewallEnv,
} from "../types.ts";
import { escapeHtml, renderDashboardHtml } from "../ui/dashboardPage.ts";

const THIRTY_DAYS_SECONDS = 30 * 86400;
const MAX_CSV_BYTES = 2 * 1024 * 1024;
const textEncoder = new TextEncoder();

const DASHBOARD_CSP =
	"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'";

/**
 * Builds a JSON HTTP response with `no-store` caching.
 */
function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"Content-Type": "application/json; charset=utf-8",
			"Cache-Control": "no-store",
		},
	});
}

/**
 * Builds a clean HTML error response for browser navigation routes without leaking secrets.
 */
function htmlErrorResponse(status: 401 | 403 | 404 | 405 | 503, message: string): Response {
	const titleByStatus: Record<401 | 403 | 404 | 405 | 503, string> = {
		401: "Authentication Required",
		403: "Access Denied",
		404: "Not Found",
		405: "Method Not Allowed",
		503: "Dashboard Authentication Not Configured",
	};

	const safeTitle = escapeHtml(titleByStatus[status]);
	const safeMessage = escapeHtml(message);

	const html = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="color-scheme" content="light dark">
	<title>${status} — ${safeTitle}</title>
	<style>
		:root { color-scheme: light dark; font-family: system-ui, -apple-system, sans-serif; }
		body { margin: 0; min-block-size: 100vh; display: grid; place-items: center; padding: 1.5rem; }
		main { max-inline-size: 480px; border: 1px solid color-mix(in srgb, currentColor 20%, transparent); border-radius: 12px; padding: 1.5rem; }
		h1 { margin: 0 0 0.5rem; font-size: 1.25rem; }
		p { margin: 0; opacity: 0.85; line-height: 1.5; }
	</style>
</head>
<body>
	<main>
		<h1>${status} — ${safeTitle}</h1>
		<p>${safeMessage}</p>
	</main>
</body>
</html>`;

	return new Response(html, {
		status,
		headers: {
			"Content-Type": "text/html; charset=utf-8",
			"Cache-Control": "no-store",
			"Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'",
		},
	});
}

/**
 * Parses and validates the dashboard period query parameter, defaulting to `"30d"`.
 */
function parsePeriod(raw: string | null): DashboardPeriod {
	if (raw === "7d" || raw === "30d" || raw === "month" || raw === "all") {
		return raw;
	}
	return "30d";
}

/**
 * Parses an optional non-negative integer query parameter.
 */
function parseOptionalInt(raw: string | null): number | undefined {
	if (!raw) {
		return undefined;
	}
	const parsed = Number.parseInt(raw, 10);
	return Number.isFinite(parsed) ? parsed : undefined;
}

/**
 * Safely parses a JSON object from a dashboard API request body.
 */
async function readJsonObject(request: Request): Promise<Record<string, unknown> | null> {
	try {
		const parsed: unknown = await request.json();
		return parsed && typeof parsed === "object" && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: null;
	} catch (error) {
		console.warn("Invalid JSON payload on dashboard API", error);
		return null;
	}
}

/**
 * Handles Cloudflare Zero Trust Access-protected `/dashboard` UI and `/dashboard/api/*` endpoints.
 *
 * Why separate from `/admin/*`: The dashboard uses Cloudflare Access JWT authentication
 * for human browser sessions, whereas `/admin/*` uses static Bearer tokens for iOS Shortcuts
 * and CLI automation.
 *
 * @param request - Incoming HTTP request.
 * @param env - Worker runtime bindings.
 * @param url - Parsed request URL.
 * @returns HTML dashboard, CSV export, or JSON API response.
 */
export async function handleDashboardRequest(
	request: Request,
	env: CallFirewallEnv,
	url: URL,
): Promise<Response> {
	const auth = await verifyCloudflareAccessRequest(request, env);
	const isApiRoute = url.pathname.startsWith("/dashboard/api/");

	if (!auth.ok) {
		if (isApiRoute) {
			return jsonResponse({ error: auth.error }, auth.status);
		}
		return htmlErrorResponse(auth.status, auth.error);
	}

	if (url.pathname === "/dashboard" || url.pathname === "/dashboard/") {
		if (request.method !== "GET") {
			return htmlErrorResponse(405, "Only GET is supported for the dashboard page.");
		}
		return new Response(renderDashboardHtml(auth.identity.email), {
			status: 200,
			headers: {
				"Content-Type": "text/html; charset=utf-8",
				"Cache-Control": "no-store",
				"Content-Security-Policy": DASHBOARD_CSP,
			},
		});
	}

	if (url.pathname === "/dashboard/api/summary") {
		if (request.method !== "GET") {
			return jsonResponse({ error: "Method Not Allowed" }, 405);
		}
		const period = parsePeriod(url.searchParams.get("period"));
		const [summary, contactsSync] = await Promise.all([
			getDashboardSummary(env.CALL_LOGS_DB, period),
			getContactsSnapshotMeta(env.ALLOWLIST_KV),
		]);
		return jsonResponse({ summary, contactsSync }, 200);
	}

	if (url.pathname === "/dashboard/api/calls") {
		if (request.method !== "GET") {
			return jsonResponse({ error: "Method Not Allowed" }, 405);
		}
		const rawPeriod = url.searchParams.get("period");
		const period = rawPeriod ? parsePeriod(rawPeriod) : undefined;
		const outcome = url.searchParams.get("outcome")?.trim() || undefined;
		const phase = url.searchParams.get("phase")?.trim() || undefined;
		const search = url.searchParams.get("search")?.trim() || undefined;
		const limit = parseOptionalInt(url.searchParams.get("limit"));
		const offset = parseOptionalInt(url.searchParams.get("offset"));

		const result = await listCallLogs(env.CALL_LOGS_DB, {
			period,
			outcome,
			phase,
			search,
			limit,
			offset,
		});
		return jsonResponse(result, 200);
	}

	if (url.pathname === "/dashboard/api/allowlist") {
		if (request.method === "GET") {
			const rawStatus = url.searchParams.get("status")?.trim();
			const status: CallerRuleStatus | undefined =
				rawStatus === "allowed" || rawStatus === "blocked" ? rawStatus : undefined;
			const search = url.searchParams.get("search")?.trim() || undefined;

			const [rules, contactsSync] = await Promise.all([
				listCallerRules(env.CALL_LOGS_DB, { status, search }),
				getContactsSnapshotMeta(env.ALLOWLIST_KV),
			]);
			return jsonResponse({ rules, contactsSync }, 200);
		}

		if (request.method === "POST") {
			const payload = await readJsonObject(request);
			if (!payload) {
				return jsonResponse({ error: "Invalid JSON body" }, 400);
			}

			const rawPhone = typeof payload.phone === "string" ? payload.phone : "";
			const phoneE164 = normalizePhoneNumber(rawPhone);
			if (!phoneE164) {
				return jsonResponse({ error: "Valid phone number is required" }, 400);
			}

			if (
				payload.status !== undefined &&
				payload.status !== "allowed" &&
				payload.status !== "blocked"
			) {
				return jsonResponse(
					{ error: "Invalid status; expected 'allowed' or 'blocked'" },
					400,
				);
			}

			const status: CallerRuleStatus = payload.status === "blocked" ? "blocked" : "allowed";
			const label =
				typeof payload.label === "string" ? payload.label.trim().slice(0, 120) : undefined;
			const reason =
				typeof payload.reason === "string" && payload.reason.trim().length > 0
					? payload.reason.trim().slice(0, 160)
					: undefined;
			const permanent = payload.permanent !== false;
			const ttlSeconds = permanent ? null : THIRTY_DAYS_SECONDS;

			const [rule] = await Promise.all([
				upsertCallerRule(env.CALL_LOGS_DB, {
					phoneE164,
					label,
					status,
					source: "manual",
					reason,
					ttlSeconds,
				}),
				setCallerRecord(
					env.ALLOWLIST_KV,
					phoneE164,
					env.CONTACT_HASH_SALT,
					status === "blocked" ? "blocked" : "verified",
					reason ?? "dashboard_manual",
					ttlSeconds,
				),
			]);

			return jsonResponse({ ok: true, rule }, 200);
		}

		if (request.method === "DELETE") {
			const payload = await readJsonObject(request);
			if (!payload) {
				return jsonResponse({ error: "Invalid JSON body" }, 400);
			}

			const rawPhone = typeof payload.phone === "string" ? payload.phone : "";
			const phoneE164 = normalizePhoneNumber(rawPhone);
			if (!phoneE164) {
				return jsonResponse({ error: "Valid phone number is required" }, 400);
			}

			await Promise.all([
				deleteCallerRule(env.CALL_LOGS_DB, phoneE164),
				deleteCallerRecord(env.ALLOWLIST_KV, phoneE164, env.CONTACT_HASH_SALT),
			]);
			return jsonResponse({ ok: true }, 200);
		}

		return jsonResponse({ error: "Method Not Allowed" }, 405);
	}

	if (url.pathname === "/dashboard/api/allowlist/csv") {
		if (request.method !== "POST") {
			return jsonResponse({ error: "Method Not Allowed" }, 405);
		}

		const payload = await readJsonObject(request);
		if (!payload) {
			return jsonResponse({ error: "Invalid JSON body" }, 400);
		}

		const csv = typeof payload.csv === "string" ? payload.csv : "";
		if (!csv.trim()) {
			return jsonResponse({ error: "Non-empty CSV text is required" }, 400);
		}

		if (textEncoder.encode(csv).byteLength > MAX_CSV_BYTES) {
			return jsonResponse({ error: "CSV payload exceeds 2 MB limit" }, 413);
		}

		if (
			payload.mode !== undefined &&
			payload.mode !== "merge" &&
			payload.mode !== "replace_csv"
		) {
			return jsonResponse({ error: "Invalid mode; expected 'merge' or 'replace_csv'" }, 400);
		}
		const mode: CsvImportMode = payload.mode === "replace_csv" ? "replace_csv" : "merge";

		const result = await importCallerRulesCsv(env.CALL_LOGS_DB, csv, mode);
		return jsonResponse({ ok: true, ...result }, 200);
	}

	if (url.pathname === "/dashboard/api/allowlist/export.csv") {
		if (request.method !== "GET") {
			return jsonResponse({ error: "Method Not Allowed" }, 405);
		}

		const csv = await exportCallerRulesCsv(env.CALL_LOGS_DB);
		return new Response(csv, {
			status: 200,
			headers: {
				"Content-Type": "text/csv; charset=utf-8",
				"Content-Disposition": 'attachment; filename="you-shall-not-ring-allowlist.csv"',
				"Cache-Control": "no-store",
			},
		});
	}

	if (isApiRoute) {
		return jsonResponse({ error: "Not Found" }, 404);
	}
	return htmlErrorResponse(404, "Dashboard route not found.");
}
