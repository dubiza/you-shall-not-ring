import { normalizePhoneNumber, verifyBearerToken } from "../security/crypto.ts";
import { readBodyTextWithLimit, withSecurityHeaders } from "../security/http.ts";
import {
	deleteCallerRecord,
	setCallerRecord,
	syncContactsSnapshot,
} from "../storage/callerList.ts";
import { deleteCallerRule, upsertCallerRule } from "../storage/callerRules.ts";
import type { CallFirewallEnv } from "../types.ts";

const THIRTY_DAYS_SECONDS = 30 * 86400;
const MAX_SYNC_BODY_BYTES = 1024 * 1024;
const MAX_SYNC_CONTACTS = 25_000;
const MAX_ADMIN_JSON_BYTES = 64 * 1024;

/**
 * Builds a consistent JSON HTTP response with `no-store` caching and security headers.
 */
function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: withSecurityHeaders({
			"Content-Type": "application/json; charset=utf-8",
			"Cache-Control": "no-store",
		}),
	});
}

/**
 * Splits delimited phone number strings (newlines, commas, semicolons) produced by iOS Shortcuts.
 */
function splitPhoneLines(rawText: string): string[] {
	return rawText
		.split(/[\r\n,;]+/)
		.map((entry) => entry.trim())
		.filter((entry) => entry.length > 0);
}

type SyncExtractResult =
	| { ok: true; numbers: string[] }
	| { ok: false; status: 400 | 413; error: string };

/**
 * Extracts raw phone numbers from either JSON (`{ numbers: string[] | string }`) or plain text,
 * enforcing strict payload byte and contact-count bounds.
 *
 * Why accept multiple formats: iOS Shortcuts' `Get Phone Numbers` action produces a
 * newline-delimited string by default, while CLI/test callers may pass a JSON array.
 */
async function extractSyncNumbers(request: Request): Promise<SyncExtractResult> {
	const contentType = request.headers.get("Content-Type")?.toLowerCase() ?? "";
	const bodyResult = await readBodyTextWithLimit(request, MAX_SYNC_BODY_BYTES);
	if (!bodyResult.ok) {
		return {
			ok: false,
			status: 413,
			error: "Contacts sync payload exceeds 1 MB limit",
		};
	}

	const rawBody = bodyResult.text;
	if (!rawBody.trim()) {
		return {
			ok: false,
			status: 400,
			error: "Expected JSON { numbers } or newline-delimited phone text",
		};
	}

	let numbers: string[] | null = null;
	if (contentType.includes("application/json")) {
		let parsed: unknown;
		try {
			parsed = JSON.parse(rawBody);
		} catch (error) {
			console.warn("Invalid JSON payload on /admin/contacts-sync", error);
			return {
				ok: false,
				status: 400,
				error: "Expected JSON { numbers } or newline-delimited phone text",
			};
		}

		if (Array.isArray(parsed)) {
			numbers = parsed.filter((item): item is string => typeof item === "string");
		} else if (parsed && typeof parsed === "object") {
			const candidate = (parsed as { numbers?: unknown }).numbers;
			if (Array.isArray(candidate)) {
				numbers = candidate.filter((item): item is string => typeof item === "string");
			} else if (typeof candidate === "string") {
				numbers = splitPhoneLines(candidate);
			}
		}
	} else {
		numbers = splitPhoneLines(rawBody);
	}

	if (!numbers) {
		return {
			ok: false,
			status: 400,
			error: "Expected JSON { numbers } or newline-delimited phone text",
		};
	}

	if (numbers.length > MAX_SYNC_CONTACTS) {
		return {
			ok: false,
			status: 413,
			error: `Contacts sync exceeds ${MAX_SYNC_CONTACTS} contact limit`,
		};
	}

	return { ok: true, numbers };
}

type AdminJsonReadResult =
	| { ok: true; payload: Record<string, unknown> }
	| { ok: false; status: 400 | 413; error: string };

/**
 * Safely parses a size-bounded JSON body on admin override endpoints.
 */
async function readJsonObject(request: Request): Promise<AdminJsonReadResult> {
	const bodyResult = await readBodyTextWithLimit(request, MAX_ADMIN_JSON_BYTES);
	if (!bodyResult.ok) {
		return bodyResult;
	}

	try {
		const parsed: unknown = JSON.parse(bodyResult.text);
		if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
			return { ok: true, payload: parsed as Record<string, unknown> };
		}
		return { ok: false, status: 400, error: "Valid JSON object is required" };
	} catch (error) {
		console.warn("Invalid JSON body on /admin/allowlist", error);
		return { ok: false, status: 400, error: "Valid JSON object is required" };
	}
}

/**
 * Handles Bearer-authenticated admin endpoints for syncing device contacts and overrides.
 *
 * @param request - Incoming HTTP request.
 * @param env - Worker runtime bindings.
 * @param url - Parsed request URL.
 * @returns JSON HTTP response (`200`, `400`, `401`, `404`, `405`, or `413`).
 */
export async function handleAdminRequest(
	request: Request,
	env: CallFirewallEnv,
	url: URL,
): Promise<Response> {
	const isAuthorized = await verifyBearerToken(
		request.headers.get("Authorization"),
		env.ADMIN_TOKEN,
	);
	if (!isAuthorized) {
		return jsonResponse({ error: "Unauthorized" }, 401);
	}

	if (url.pathname === "/admin/contacts-sync") {
		if (request.method !== "POST") {
			return jsonResponse({ error: "Method Not Allowed" }, 405);
		}

		const extracted = await extractSyncNumbers(request);
		if (!extracted.ok) {
			return jsonResponse({ error: extracted.error }, extracted.status);
		}

		const result = await syncContactsSnapshot(
			env.ALLOWLIST_KV,
			extracted.numbers,
			env.CONTACT_HASH_SALT,
		);
		return jsonResponse({ ok: true, ...result }, 200);
	}

	if (url.pathname === "/admin/allowlist") {
		if (request.method === "POST") {
			const bodyRead = await readJsonObject(request);
			if (!bodyRead.ok) {
				return jsonResponse({ error: bodyRead.error }, bodyRead.status);
			}
			const payload = bodyRead.payload;

			const rawPhone = typeof payload.phone === "string" ? payload.phone : "";
			const normalized = normalizePhoneNumber(rawPhone);
			if (!normalized) {
				return jsonResponse({ error: "Valid phone number is required" }, 400);
			}

			const rawStatus = payload.status;
			const status = rawStatus === "blocked" ? "blocked" : "verified";
			const reason =
				typeof payload.reason === "string" ? payload.reason.trim().slice(0, 120) : undefined;

			// Mirror overrides in both KV (fast edge hash lookup) and D1 (dashboard rule management).
			await Promise.all([
				setCallerRecord(
					env.ALLOWLIST_KV,
					normalized,
					env.CONTACT_HASH_SALT,
					status,
					reason,
				),
				upsertCallerRule(env.CALL_LOGS_DB, {
					phoneE164: normalized,
					status: status === "blocked" ? "blocked" : "allowed",
					source: "admin_api",
					reason,
					ttlSeconds: status === "blocked" ? null : THIRTY_DAYS_SECONDS,
				}),
			]);
			return jsonResponse({ ok: true, status }, 200);
		}

		if (request.method === "DELETE") {
			const bodyRead = await readJsonObject(request);
			if (!bodyRead.ok) {
				return jsonResponse({ error: bodyRead.error }, bodyRead.status);
			}
			const payload = bodyRead.payload;

			const rawPhone = typeof payload.phone === "string" ? payload.phone : "";
			const normalized = normalizePhoneNumber(rawPhone);
			if (!normalized) {
				return jsonResponse({ error: "Valid phone number is required" }, 400);
			}

			await Promise.all([
				deleteCallerRecord(env.ALLOWLIST_KV, normalized, env.CONTACT_HASH_SALT),
				deleteCallerRule(env.CALL_LOGS_DB, normalized),
			]);
			return jsonResponse({ ok: true }, 200);
		}

		return jsonResponse({ error: "Method Not Allowed" }, 405);
	}

	return jsonResponse({ error: "Not Found" }, 404);
}
