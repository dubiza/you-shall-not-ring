const textEncoder = new TextEncoder();

/**
 * Resolves the external public URL Twilio signed, honoring forwarding headers if present.
 *
 * Why forwarded headers matter: Twilio signs the exact public HTTPS URL configured in its
 * console, whereas reverse proxies or local tunnels may rewrite `request.url` internally.
 *
 * @param request - Incoming HTTP request.
 * @returns Canonical URL string including scheme, host, pathname, and query string.
 */
export function getPublicRequestUrl(request: Request): string {
	const parsed = new URL(request.url);
	const forwardedProto = request.headers.get("X-Forwarded-Proto")?.split(",")[0]?.trim();
	const forwardedHost = request.headers.get("X-Forwarded-Host")?.split(",")[0]?.trim();

	if (forwardedProto === "http" || forwardedProto === "https") {
		parsed.protocol = `${forwardedProto}:`;
	}
	if (forwardedHost) {
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
 * Decodes a Base64 signature safely without throwing on malformed headers.
 *
 * @param encoded - Raw `X-Twilio-Signature` header value.
 * @returns Decoded bytes, or `null` if invalid Base64.
 */
function decodeBase64Bytes(encoded: string): Uint8Array | null {
	try {
		const binary = atob(encoded);
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
