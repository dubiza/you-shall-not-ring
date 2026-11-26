const textEncoder = new TextEncoder();
const TWILIO_HMAC_SHA1_BASE64_REGEX = /^[A-Za-z0-9+/]{27}=$/;
const VALID_FORWARDED_HOST_REGEX = /^[a-zA-Z0-9.-]+(?::\d{1,5})?$/;

/**
 * Checks whether the request arrived at an unencrypted local dev/tunnel origin where
 * `X-Forwarded-*` headers are legitimately added by a local reverse proxy.
 */
function isLocalProxyOrigin(parsedUrl: URL): boolean {
	if (parsedUrl.protocol !== "http:") {
		return false;
	}
	const host = parsedUrl.hostname.toLowerCase();
	return (
		host === "localhost" ||
		host === "127.0.0.1" ||
		host === "::1" ||
		host === "[::1]" ||
		host.endsWith(".local")
	);
}

/**
 * Resolves the external public URL Twilio signed.
 *
 * Why ignore `X-Forwarded-*` on production `https:` requests: Cloudflare Workers already receive
 * the authoritative public `request.url` and do not strip client-supplied `X-Forwarded-Host`,
 * so honoring untrusted headers on `https:` would enable cross-host webhook replay within the
 * same Twilio account. Forwarding headers are honored only on local `http:` dev tunnels.
 *
 * @param request - Incoming HTTP request.
 * @returns Canonical URL string including scheme, host, pathname, and query string.
 */
export function getPublicRequestUrl(request: Request): string {
	const parsed = new URL(request.url);
	if (!isLocalProxyOrigin(parsed)) {
		return parsed.toString();
	}

	const forwardedProto = request.headers.get("X-Forwarded-Proto")?.split(",")[0]?.trim().toLowerCase();
	const forwardedHost = request.headers.get("X-Forwarded-Host")?.split(",")[0]?.trim();

	if (forwardedProto === "http" || forwardedProto === "https") {
		parsed.protocol = `${forwardedProto}:`;
	}
	if (forwardedHost && VALID_FORWARDED_HOST_REGEX.test(forwardedHost)) {
		parsed.host = forwardedHost;
	}

	return parsed.toString();
}

/**
 * Builds the exact canonical payload string required by Twilio's webhook signature spec.
 *
 * @param url - Public URL including query parameters.
 * @param params - Parsed `application/x-www-form-urlencoded` POST body parameters.
 * @returns Concatenated URL + ASCII-sorted `keyvalue` pairs.
 */
function buildTwilioSignedPayload(url: string, params: Record<string, string>): string {
	// Twilio specifies standard code-unit (ASCII) sort rather than locale-aware collation.
	const sortedKeys = Object.keys(params).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
	let payload = url;
	for (const key of sortedKeys) {
		payload += `${key}${params[key] ?? ""}`;
	}
	return payload;
}

/**
 * Computes a Base64-encoded `X-Twilio-Signature` (HMAC-SHA1) for testing and verification.
 *
 * @param url - Full webhook URL (including query string).
 * @param params - Form body key/value parameters.
 * @param authToken - Twilio Auth Token secret.
 * @returns Base64 signature string.
 */
export async function computeTwilioSignature(
	url: string,
	params: Record<string, string>,
	authToken: string,
): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		textEncoder.encode(authToken),
		{ name: "HMAC", hash: "SHA-1" },
		false,
		["sign"],
	);

	const payload = buildTwilioSignedPayload(url, params);
	const signatureBuffer = await crypto.subtle.sign("HMAC", key, textEncoder.encode(payload));
	const signatureBytes = new Uint8Array(signatureBuffer);

	let binary = "";
	for (const byte of signatureBytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary);
}

/**
 * Validates that an `X-Twilio-Signature` header matches canonical 20-byte HMAC-SHA1 Base64 syntax.
 *
 * Why pre-check format before reading the request body: Allows `/voice/*` to reject
 * missing or malformed unauthenticated requests before buffering POST bodies in memory.
 *
 * @param headerValue - Raw `X-Twilio-Signature` header value.
 * @returns `true` if syntactically valid 28-character Base64 representing 20 bytes.
 */
export function hasValidTwilioSignatureFormat(headerValue: string | null): boolean {
	const trimmed = headerValue?.trim() ?? "";
	return TWILIO_HMAC_SHA1_BASE64_REGEX.test(trimmed);
}

/**
 * Decodes a canonical 20-byte HMAC-SHA1 Base64 signature safely without throwing on malformed headers.
 *
 * @param encoded - Raw `X-Twilio-Signature` header value.
 * @returns Decoded 20-byte array, or `null` if invalid Base64 or wrong byte length.
 */
function decodeBase64Bytes(encoded: string): Uint8Array | null {
	if (!TWILIO_HMAC_SHA1_BASE64_REGEX.test(encoded)) {
		return null;
	}
	try {
		const binary = atob(encoded);
		if (binary.length !== 20) {
			return null;
		}
		const bytes = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i += 1) {
			bytes[i] = binary.charCodeAt(i);
		}
		return bytes;
	} catch (error) {
		console.warn("Malformed Base64 in X-Twilio-Signature header", error);
		return null;
	}
}

/**
 * Verifies an incoming Twilio webhook request using Web Crypto `HMAC-SHA1`.
 *
 * Why mandatory verification: Without signature checks, anyone discovering the Worker URL
 * could trigger Workers AI calls or force calls through to the user's SIP endpoint.
 *
 * @param request - Incoming HTTP request from Twilio.
 * @param params - Parsed form parameters from the POST body.
 * @param authToken - Configured `TWILIO_AUTH_TOKEN` secret.
 * @returns `true` if the `X-Twilio-Signature` header is authentic.
 */
export async function verifyTwilioRequest(
	request: Request,
	params: Record<string, string>,
	authToken: string,
): Promise<boolean> {
	if (!authToken) {
		console.error("TWILIO_AUTH_TOKEN secret is not configured");
		return false;
	}

	const headerSignature = request.headers.get("X-Twilio-Signature")?.trim();
	if (!headerSignature) {
		return false;
	}

	const signatureBytes = decodeBase64Bytes(headerSignature);
	if (!signatureBytes) {
		return false;
	}

	const key = await crypto.subtle.importKey(
		"raw",
		textEncoder.encode(authToken),
		{ name: "HMAC", hash: "SHA-1" },
		false,
		["verify"],
	);

	const publicUrl = getPublicRequestUrl(request);
	const payload = buildTwilioSignedPayload(publicUrl, params);

	return crypto.subtle.verify(
		"HMAC",
		key,
		signatureBytes,
		textEncoder.encode(payload),
	);
}
