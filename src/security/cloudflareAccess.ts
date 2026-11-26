import type { AccessIdentity, CallFirewallEnv } from "../types.ts";

const JWKS_CACHE_TTL_MS = 10 * 60 * 1000;
const CLOCK_SKEW_SECONDS = 30;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

interface CachedJwks {
	fetchedAtMs: number;
	keysByKid: Map<string, CryptoKey>;
}

/**
 * Why key the JWKS cache by `fetcher` instance first and issuer URL second:
 * Production callers share `globalThis.fetch` and get the full 10-minute per-issuer cache,
 * while unit tests injecting distinct mock `fetcher` doubles remain isolated from each other.
 */
const jwksCacheByFetcher = new WeakMap<typeof fetch, Map<string, CachedJwks>>();

/**
 * Verification outcome returned by {@link verifyCloudflareAccessRequest}.
 */
export type AccessVerificationResult =
	| { ok: true; identity: AccessIdentity }
	| { ok: false; status: 401 | 403 | 503; error: string };

interface JwtHeader {
	alg?: unknown;
	kid?: unknown;
}

interface JwtPayload {
	iss?: unknown;
	aud?: unknown;
	exp?: unknown;
	nbf?: unknown;
	email?: unknown;
	sub?: unknown;
}

interface JwksResponse {
	keys?: Array<JsonWebKey & { kid?: unknown; use?: unknown; alg?: unknown; kty?: unknown }>;
}

/**
 * Normalizes `CF_ACCESS_TEAM_DOMAIN` into the canonical HTTPS issuer origin without trailing slashes.
 */
function normalizeIssuer(teamDomain: string): string {
	const stripped = teamDomain.trim().replace(/^https?:\/\//i, "").replace(/\/+$/, "");
	return `https://${stripped}`;
}

/**
 * Extracts the Cloudflare Access JWT from the `Cf-Access-Jwt-Assertion` header or `CF_Authorization` cookie.
 */
function extractAccessJwt(request: Request): string | null {
	const headerJwt = request.headers.get("Cf-Access-Jwt-Assertion")?.trim();
	if (headerJwt) {
		return headerJwt;
	}

	const cookieHeader = request.headers.get("Cookie");
	if (!cookieHeader) {
		return null;
	}

	for (const part of cookieHeader.split(";")) {
		const eqIdx = part.indexOf("=");
		if (eqIdx === -1) {
			continue;
		}
		const name = part.slice(0, eqIdx).trim();
		if (name !== "CF_Authorization") {
			continue;
		}
		let rawValue = part.slice(eqIdx + 1).trim();
		if (rawValue.startsWith('"') && rawValue.endsWith('"') && rawValue.length >= 2) {
			rawValue = rawValue.slice(1, -1);
		}
		if (rawValue.includes("%")) {
			try {
				rawValue = decodeURIComponent(rawValue);
			} catch (error) {
				console.warn("Malformed URI encoding in CF_Authorization cookie", error);
			}
		}
		return rawValue.length > 0 ? rawValue : null;
	}

	return null;
}

/**
 * Decodes a Base64URL-encoded string into raw bytes.
 */
function decodeBase64Url(segment: string): Uint8Array {
	const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
	const padding = (4 - (normalized.length % 4)) % 4;
	const padded = normalized + "=".repeat(padding);
	const binary = atob(padded);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i += 1) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

/**
 * Decodes and JSON-parses a Base64URL-encoded JWT header or payload segment.
 */
function decodeJwtJsonSegment<T>(segment: string): T {
	const bytes = decodeBase64Url(segment);
	const json = textDecoder.decode(bytes);
	return JSON.parse(json) as T;
}

/**
 * Fetches and imports RSA-256 public verification keys from Cloudflare Access JWKS.
 */
async function loadJwksForIssuer(
	issuer: string,
	fetcher: typeof fetch,
	forceRefresh: boolean,
): Promise<Map<string, CryptoKey>> {
	let issuerCache = jwksCacheByFetcher.get(fetcher);
	if (!issuerCache) {
		issuerCache = new Map<string, CachedJwks>();
		jwksCacheByFetcher.set(fetcher, issuerCache);
	}

	const nowMs = Date.now();
	const cached = issuerCache.get(issuer);
	if (!forceRefresh && cached && nowMs - cached.fetchedAtMs < JWKS_CACHE_TTL_MS) {
		return cached.keysByKid;
	}

	const certsUrl = `${issuer}/cdn-cgi/access/certs`;
	const response = await fetcher(certsUrl, {
		headers: { Accept: "application/json" },
	});

	if (!response.ok) {
		throw new Error(`JWKS fetch failed with HTTP ${response.status} from ${certsUrl}`);
	}

	const body = (await response.json()) as JwksResponse;
	const keysByKid = new Map<string, CryptoKey>();

	for (const jwk of body.keys ?? []) {
		if (typeof jwk.kid !== "string" || jwk.kid.length === 0) {
			continue;
		}
		if (jwk.kty !== "RSA") {
			continue;
		}
		if (jwk.use !== undefined && jwk.use !== "sig") {
			continue;
		}
		if (jwk.alg !== undefined && jwk.alg !== "RS256") {
			continue;
		}

		try {
			const cryptoKey = await crypto.subtle.importKey(
				"jwk",
				jwk,
				{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
				false,
				["verify"],
			);
			keysByKid.set(jwk.kid, cryptoKey);
		} catch (error) {
			console.warn(`Skipping unusable Access JWK kid=${jwk.kid}`, error);
		}
	}

	issuerCache.set(issuer, {
		fetchedAtMs: nowMs,
		keysByKid,
	});

	return keysByKid;
}

/**
 * Verifies a Cloudflare Zero Trust Access JWT attached to an incoming dashboard request.
 *
 * Why fail closed on missing configuration (`503`): If `CF_ACCESS_TEAM_DOMAIN` or
 * `CF_ACCESS_AUD` is unset, the Worker must never silently expose call logs or allowlists.
 *
 * @param request - Incoming HTTP request carrying `Cf-Access-Jwt-Assertion` or `CF_Authorization`.
 * @param env - Worker environment configuration containing Access domain and audience tag.
 * @param fetcher - Optional `fetch` override for unit tests.
 * @returns Verified {@link AccessIdentity} or an HTTP failure status (`401`, `403`, or `503`).
 */
export async function verifyCloudflareAccessRequest(
	request: Request,
	env: CallFirewallEnv,
	fetcher: typeof fetch = fetch,
): Promise<AccessVerificationResult> {
	const teamDomain = env.CF_ACCESS_TEAM_DOMAIN?.trim();
	const expectedAud = env.CF_ACCESS_AUD?.trim();

	if (!teamDomain || !expectedAud) {
		return {
			ok: false,
			status: 503,
			error: "Cloudflare Access is not configured (missing CF_ACCESS_TEAM_DOMAIN or CF_ACCESS_AUD)",
		};
	}

	const token = extractAccessJwt(request);
	if (!token) {
		return {
			ok: false,
			status: 401,
			error: "Missing Cloudflare Access authentication token",
		};
	}

	const parts = token.split(".");
	if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
		return {
			ok: false,
			status: 403,
			error: "Malformed Cloudflare Access JWT",
		};
	}

	const [headerB64, payloadB64, signatureB64] = parts;

	let header: JwtHeader;
	let payload: JwtPayload;
	let signatureBytes: Uint8Array;
	try {
		header = decodeJwtJsonSegment<JwtHeader>(headerB64);
		payload = decodeJwtJsonSegment<JwtPayload>(payloadB64);
		signatureBytes = decodeBase64Url(signatureB64);
	} catch (error) {
		console.warn("Failed to decode Cloudflare Access JWT", error);
		return {
			ok: false,
			status: 403,
			error: "Invalid Cloudflare Access JWT encoding",
		};
	}

	if (header.alg !== "RS256" || typeof header.kid !== "string" || header.kid.trim().length === 0) {
		return {
			ok: false,
			status: 403,
			error: "Unsupported or missing Access JWT signing algorithm/kid",
		};
	}

	const issuer = normalizeIssuer(teamDomain);

	let keysByKid: Map<string, CryptoKey>;
	try {
		keysByKid = await loadJwksForIssuer(issuer, fetcher, false);
	} catch (error) {
		console.error("Failed to fetch Cloudflare Access JWKS", error);
		return {
			ok: false,
			status: 503,
			error: "Unable to retrieve Cloudflare Access signing certificates",
		};
	}

	let signingKey = keysByKid.get(header.kid);
	if (!signingKey) {
		try {
			// Single refresh handles Cloudflare Access key rotation without caching misses forever.
			keysByKid = await loadJwksForIssuer(issuer, fetcher, true);
			signingKey = keysByKid.get(header.kid);
		} catch (error) {
			console.error("Failed to refresh Cloudflare Access JWKS", error);
			return {
				ok: false,
				status: 503,
				error: "Unable to refresh Cloudflare Access signing certificates",
			};
		}
	}

	if (!signingKey) {
		return {
			ok: false,
			status: 403,
			error: "Unknown Cloudflare Access signing key",
		};
	}

	const signedInput = textEncoder.encode(`${headerB64}.${payloadB64}`);
	const signatureValid = await crypto.subtle.verify(
		"RSASSA-PKCS1-v1_5",
		signingKey,
		signatureBytes,
		signedInput,
	);

	if (!signatureValid) {
		return {
			ok: false,
			status: 403,
			error: "Invalid Cloudflare Access JWT signature",
		};
	}

	if (payload.iss !== issuer) {
		return {
			ok: false,
			status: 403,
			error: "Cloudflare Access JWT issuer mismatch",
		};
	}

	const audMatches = Array.isArray(payload.aud)
		? payload.aud.includes(expectedAud)
		: payload.aud === expectedAud;
	if (!audMatches) {
		return {
			ok: false,
			status: 403,
			error: "Cloudflare Access JWT audience mismatch",
		};
	}

	const nowSec = Math.floor(Date.now() / 1000);
	if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp) || payload.exp <= nowSec - CLOCK_SKEW_SECONDS) {
		return {
			ok: false,
			status: 403,
			error: "Cloudflare Access JWT has expired",
		};
	}

	if (
		payload.nbf !== undefined &&
		(typeof payload.nbf !== "number" || !Number.isFinite(payload.nbf) || payload.nbf > nowSec + CLOCK_SKEW_SECONDS)
	) {
		return {
			ok: false,
			status: 403,
			error: "Cloudflare Access JWT is not yet valid",
		};
	}

	return {
		ok: true,
		identity: {
			email: typeof payload.email === "string" ? payload.email : "",
			sub: typeof payload.sub === "string" ? payload.sub : "",
		},
	};
}
