import { normalizePhoneNumber, verifyBearerToken } from "../security/crypto.ts";
import {
	deleteCallerRecord,
	setCallerRecord,
	syncContactsSnapshot,
} from "../storage/callerList.ts";
import { deleteCallerRule, upsertCallerRule } from "../storage/callerRules.ts";
import type { CallFirewallEnv } from "../types.ts";

const THIRTY_DAYS_SECONDS = 30 * 86400;

/**
 * Builds a consistent JSON HTTP response with `no-store` caching.
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
 * Splits delimited phone number strings (newlines, commas, semicolons) produced by iOS Shortcuts.
 */
function splitPhoneLines(rawText: string): string[] {
	return rawText
		.split(/[\r\n,;]+/)
		.map((entry) => entry.trim())
		.filter((entry) => entry.length > 0);
}

/**
 * Extracts raw phone numbers from either JSON (`{ numbers: string[] | string }`) or plain text.
 *
 * Why accept multiple formats: iOS Shortcuts' `Get Phone Numbers` action produces a
 * newline-delimited string by default, while CLI/test callers may pass a JSON array.
 */
async function extractSyncNumbers(request: Request): Promise<string[] | null> {
	const contentType = request.headers.get("Content-Type")?.toLowerCase() ?? "";
	const rawBody = await request.text();
	if (!rawBody.trim()) {
		return null;
	}

	if (contentType.includes("application/json")) {
		let parsed: unknown;
		try {
			parsed = JSON.parse(rawBody);
		} catch (error) {
			console.warn("Invalid JSON payload on /admin/contacts-sync", error);
			return null;
		}

		if (Array.isArray(parsed)) {
			return parsed.filter((item): item is string => typeof item === "string");
		}

		if (parsed && typeof parsed === "object") {
			const candidate = (parsed as { numbers?: unknown }).numbers;
			if (Array.isArray(candidate)) {
				return candidate.filter((item): item is string => typeof item === "string");
			}
			if (typeof candidate === "string") {
				return splitPhoneLines(candidate);
			}
		}

		return null;
	}

	return splitPhoneLines(rawBody);
}

/**
 * Safely parses a JSON body on admin override endpoints.
 */
async function readJsonObject(request: Request): Promise<Record<string, unknown> | null> {
	try {
		const parsed: unknown = await request.json();
		return parsed && typeof parsed === "object" && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: null;
	} catch (error) {
		console.warn("Invalid JSON body on /admin/allowlist", error);
		return null;
	}
}

/**
 * Handles Bearer-authenticated admin endpoints for syncing device contacts and overrides.
 *
 * @param request - Incoming HTTP request.
 * @param env - Worker runtime bindings.
 * @param url - Parsed request URL.
 * @returns JSON HTTP response (`200`, `400`, `401`, `404`, or `405`).
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

		const numbers = await extractSyncNumbers(request);
		if (!numbers) {
			return jsonResponse(
				{ error: "Expected JSON { numbers } or newline-delimited phone text" },
				400,
			);
		}

		const result = await syncContactsSnapshot(
			env.ALLOWLIST_KV,
			numbers,
			env.CONTACT_HASH_SALT,
		);
		return jsonResponse({ ok: true, ...result }, 200);
	}

	if (url.pathname === "/admin/allowlist") {
		if (request.method === "POST") {
			const payload = await readJsonObject(request);
			const rawPhone = typeof payload?.phone === "string" ? payload.phone : "";
			const normalized = normalizePhoneNumber(rawPhone);
			if (!normalized) {
				return jsonResponse({ error: "Valid phone number is required" }, 400);
			}

			const rawStatus = payload?.status;
			const status = rawStatus === "blocked" ? "blocked" : "verified";
			const reason =
				typeof payload?.reason === "string" ? payload.reason.trim().slice(0, 120) : undefined;

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
			const payload = await readJsonObject(request);
			const rawPhone = typeof payload?.phone === "string" ? payload.phone : "";
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
