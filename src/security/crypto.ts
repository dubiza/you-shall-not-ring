const textEncoder = new TextEncoder();

const ANONYMOUS_TOKENS = new Set([
	"anonymous",
	"restricted",
	"unknown",
	"private",
	"blocked",
	"unavailable",
	"withheld",
]);

/**
 * Normalizes a raw phone string into E.164 format (e.g. `+14155550199`).
 *
 * Why strict normalization: iPhone Contacts store mixed punctuation, while Twilio
 * sends E.164 strings and sometimes literal words like `"anonymous"`. Rejecting
 * non-dialable labels prevents attackers or masked numbers from ever entering an allowlist.
 *
 * @param raw - Incoming Caller ID or contact phone string.
 * @param defaultCountryCode - Country calling code applied to 10-digit numbers (defaults to `"1"` for US/NANP).
 * @returns Canonical E.164 phone number, or `null` if invalid/anonymous.
 */
export function normalizePhoneNumber(raw: string, defaultCountryCode = "1"): string | null {
	const trimmed = raw.trim();
	if (!trimmed) {
		return null;
	}

	if (ANONYMOUS_TOKENS.has(trimmed.toLowerCase())) {
		return null;
	}

	const compact = trimmed.replace(/[\s().-]/g, "");

	if (compact.startsWith("+")) {
		return /^\+[1-9]\d{6,14}$/.test(compact) ? compact : null;
	}

	if (compact.startsWith("00")) {
		const converted = `+${compact.slice(2)}`;
		return /^\+[1-9]\d{6,14}$/.test(converted) ? converted : null;
	}

	if (/^\d{10}$/.test(compact)) {
		const e164 = `+${defaultCountryCode}${compact}`;
		return /^\+[1-9]\d{6,14}$/.test(e164) ? e164 : null;
	}

	if (defaultCountryCode === "1" && /^1\d{10}$/.test(compact)) {
		return `+${compact}`;
	}

	return null;
}

function digestToHex128(signature: ArrayBuffer): string {
	const bytes = new Uint8Array(signature).subarray(0, 16);
	let hex = "";
	for (const byte of bytes) {
		hex += byte.toString(16).padStart(2, "0");
	}
	return hex;
}

/**
 * Imports the HMAC-SHA256 signing key for phone number hashing once.
 */
async function importPhoneHashKey(salt: string): Promise<CryptoKey> {
	if (!salt) {
		throw new Error("CONTACT_HASH_SALT secret must be configured and non-empty");
	}
	return crypto.subtle.importKey(
		"raw",
		textEncoder.encode(salt),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
}

/**
 * Computes a salted, non-reversible 128-bit HMAC-SHA256 hex digest for an E.164 phone number.
 *
 * Why salted HMAC instead of plaintext numbers: Keeps personal contacts and caller logs
 * anonymized inside Workers KV while preserving deterministic O(1) lookups across syncs.
 * Truncating to 32 hex chars (128 bits) keeps the single-key contacts snapshot compact.
 *
 * @param normalizedE164 - Canonical E.164 number.
 * @param salt - Secret salt configured via `CONTACT_HASH_SALT`.
 * @returns 32-character lowercase hex digest.
 */
export async function hashPhoneNumber(normalizedE164: string, salt: string): Promise<string> {
	const key = await importPhoneHashKey(salt);
	const signature = await crypto.subtle.sign("HMAC", key, textEncoder.encode(normalizedE164));
	return digestToHex128(signature);
}

/**
 * Computes salted 128-bit HMAC-SHA256 hex digests for a batch of E.164 numbers,
 * importing the HMAC key once to stay well within Cloudflare Workers CPU budgets.
 *
 * @param normalizedNumbers - Array of canonical E.164 phone numbers.
 * @param salt - Secret salt configured via `CONTACT_HASH_SALT`.
 * @returns Array of 32-character lowercase hex digests in matching order.
 */
export async function hashPhoneNumbersBatch(
	normalizedNumbers: readonly string[],
	salt: string,
): Promise<string[]> {
	const key = await importPhoneHashKey(salt);
	return Promise.all(
		normalizedNumbers.map(async (number) => {
			const signature = await crypto.subtle.sign("HMAC", key, textEncoder.encode(number));
			return digestToHex128(signature);
		}),
	);
}

/**
 * Compares two secret strings in constant time by comparing their SHA-256 digests.
 *
 * Why digest comparison: Hashing both inputs normalizes differing lengths to 32 bytes
 * before XOR comparison, avoiding length side-channel leaks in standard JS string checks.
 *
 * @param left - Provided secret or token string.
 * @param right - Expected secret or token string.
 * @returns `true` if both strings are identical.
 */
export async function constantTimeEqual(left: string, right: string): Promise<boolean> {
	const [digestLeft, digestRight] = await Promise.all([
		crypto.subtle.digest("SHA-256", textEncoder.encode(left)),
		crypto.subtle.digest("SHA-256", textEncoder.encode(right)),
	]);

	const bytesLeft = new Uint8Array(digestLeft);
	const bytesRight = new Uint8Array(digestRight);

	let diff = 0;
	for (let i = 0; i < bytesLeft.length; i += 1) {
		diff |= (bytesLeft[i] ?? 0) ^ (bytesRight[i] ?? 0);
	}
	return diff === 0;
}

/**
 * Validates an HTTP `Authorization: Bearer <token>` header in constant time.
 *
 * @param authHeader - Value of the `Authorization` request header.
 * @param expectedToken - Configured `ADMIN_TOKEN` secret.
 * @returns `true` if a valid matching Bearer token was supplied.
 */
export async function verifyBearerToken(
	authHeader: string | null,
	expectedToken: string,
): Promise<boolean> {
	if (!authHeader || !expectedToken) {
		return false;
	}

	const match = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
	const providedToken = match?.[1]?.trim();
	if (!providedToken) {
		return false;
	}

	return constantTimeEqual(providedToken, expectedToken);
}
