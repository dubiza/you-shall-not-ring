const textDecoder = new TextDecoder();

/**
 * Baseline browser and HTTP security headers attached to Worker responses.
 *
 * Why enforce globally: Prevents MIME-sniffing (`nosniff`), leaks of sensitive URLs/query
 * parameters via `Referer` (`no-referrer`), clickjacking (`X-Frame-Options: DENY`), and
 * unintended browser sensor/feature access (`Permissions-Policy`).
 */
export const BASE_SECURITY_HEADERS: Readonly<Record<string, string>> = {
	"X-Content-Type-Options": "nosniff",
	"Referrer-Policy": "no-referrer",
	"Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
	"X-Frame-Options": "DENY",
};

/**
 * Merges {@link BASE_SECURITY_HEADERS} as defaults with caller-supplied HTTP headers.
 *
 * @param headers - Optional response-specific headers that override or extend defaults.
 * @returns Combined {@link Headers} instance.
 */
export function withSecurityHeaders(headers?: HeadersInit): Headers {
	const merged = new Headers(BASE_SECURITY_HEADERS);
	if (headers) {
		const extra = new Headers(headers);
		extra.forEach((value, key) => {
			merged.set(key, value);
		});
	}
	return merged;
}

/**
 * Generates a fresh 128-bit cryptographic nonce encoded as Base64 for per-request CSP.
 *
 * Why per-request nonces: Replacing `script-src 'unsafe-inline'` with a CSPRNG nonce
 * ensures only the Worker-rendered script tag can execute even if HTML were injected.
 *
 * @returns Base64-encoded 16-byte nonce string.
 */
export function generateCspNonce(): string {
	const bytes = new Uint8Array(16);
	crypto.getRandomValues(bytes);
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary);
}

/**
 * Builds the strict Content-Security-Policy header for the authenticated `/dashboard` document.
 *
 * @param nonce - Cryptographic nonce embedded on the dashboard's `<script>` element.
 * @returns Complete CSP header directive string.
 */
export function buildDashboardCsp(nonce: string): string {
	return (
		`default-src 'self'; ` +
		`script-src 'nonce-${nonce}'; ` +
		`style-src 'unsafe-inline'; ` +
		`img-src 'self' data:; ` +
		`connect-src 'self'; ` +
		`base-uri 'none'; ` +
		`form-action 'self'; ` +
		`object-src 'none'; ` +
		`frame-ancestors 'none'`
	);
}

/**
 * Result of verifying same-origin CSRF defenses on state-changing browser API requests.
 */
export type SameOriginCheckResult =
	| { ok: true }
	| { ok: false; status: 403 | 415; error: string };

/**
 * Enforces layered CSRF protections on state-mutating browser API routes (`POST`, `DELETE`, etc.).
 *
 * Why three independent checks:
 * - `Sec-Fetch-Site` blocks cross-site and sibling-subdomain (`same-site`) browser fetches.
 * - Strict `Origin === url.origin` verification protects browsers or proxies omitting Fetch Metadata.
 * - Requiring `Content-Type: application/json` forces a CORS preflight (which fails closed
 *   without CORS headers) and rejects simple-request `text/plain` or form submissions.
 *
 * @param request - Incoming HTTP request.
 * @param url - Parsed request URL whose `origin` is authoritative.
 * @returns Verification result or `403`/`415` error details.
 */
export function verifySameOriginMutation(request: Request, url: URL): SameOriginCheckResult {
	if (request.method === "GET" || request.method === "HEAD") {
		return { ok: true };
	}

	const secFetchSite = request.headers.get("Sec-Fetch-Site")?.trim().toLowerCase();
	if (secFetchSite && secFetchSite !== "same-origin") {
		return {
			ok: false,
			status: 403,
			error: "Cross-site request blocked by Fetch Metadata policy",
		};
	}

	const originHeader = request.headers.get("Origin")?.trim();
	if (!originHeader || originHeader !== url.origin) {
		return {
			ok: false,
			status: 403,
			error: "Missing or mismatched Origin header",
		};
	}

	const contentType = request.headers.get("Content-Type")?.trim().toLowerCase() ?? "";
	if (!contentType.startsWith("application/json")) {
		return {
			ok: false,
			status: 415,
			error: "Expected Content-Type: application/json",
		};
	}

	return { ok: true };
}

/**
 * Result of reading a bounded HTTP request body stream as UTF-8 text.
 */
export type BodyReadResult =
	| { ok: true; text: string }
	| { ok: false; status: 413; error: string };

/**
 * Reads a request body stream up to `maxBytes`, aborting immediately on oversized payloads.
 *
 * Why stream-bounded reading instead of `request.text()` / `request.json()`:
 * Checking `Content-Length` alone can be bypassed with chunked transfer encoding; counting
 * bytes per stream chunk stops unauthenticated callers from exhausting Worker isolate memory.
 *
 * @param request - Incoming HTTP request.
 * @param maxBytes - Maximum permitted payload size in bytes.
 * @returns Decoded UTF-8 body string or `413` payload-too-large error.
 */
export async function readBodyTextWithLimit(
	request: Request,
	maxBytes: number,
): Promise<BodyReadResult> {
	const rawContentLength = request.headers.get("Content-Length")?.trim();
	if (rawContentLength) {
		const declaredLength = Number.parseInt(rawContentLength, 10);
		if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
			return {
				ok: false,
				status: 413,
				error: `Request body exceeds ${maxBytes} byte limit`,
			};
		}
	}

	if (!request.body) {
		return { ok: true, text: "" };
	}

	const reader = request.body.getReader();
	const chunks: Uint8Array[] = [];
	let totalBytes = 0;

	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) {
				break;
			}
			if (!value || value.byteLength === 0) {
				continue;
			}

			totalBytes += value.byteLength;
			if (totalBytes > maxBytes) {
				await reader.cancel("Payload exceeds maximum allowed size").catch((err: unknown) => {
					console.warn("Failed to cancel oversized request stream", err);
				});
				return {
					ok: false,
					status: 413,
					error: `Request body exceeds ${maxBytes} byte limit`,
				};
			}
			chunks.push(value);
		}
	} finally {
		reader.releaseLock();
	}

	const combined = new Uint8Array(totalBytes);
	let offset = 0;
	for (const chunk of chunks) {
		combined.set(chunk, offset);
		offset += chunk.byteLength;
	}

	return {
		ok: true,
		text: textDecoder.decode(combined),
	};
}
