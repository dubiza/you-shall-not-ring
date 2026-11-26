import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { classifyCallerIntent, sanitizeWhisperSummary } from "../src/ai/intentClassifier.ts";
import worker from "../src/index.ts";
import { verifyCloudflareAccessRequest } from "../src/security/cloudflareAccess.ts";
import { computeTwilioSignature } from "../src/security/twilioSignature.ts";
import {
	exportCallerRulesCsv,
	importCallerRulesCsv,
	lookupCallerRule,
	parseContactsCsv,
	upsertCallerRule,
} from "../src/storage/callerRules.ts";
import type { CallerRuleRow } from "../src/types.ts";
import {
	buildClefResponse,
	createSignedTwilioRequest,
	createTestEnv,
	MockAiRunner,
	SqliteD1Store,
} from "./helpers/mockEnv.ts";

const BASE_URL = "https://firewall.example.com";
const TEAM_DOMAIN = "firewall-test.cloudflareaccess.com";
const ACCESS_AUD = "test-access-aud-12345";
const textEncoder = new TextEncoder();

function encodeBase64Url(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function signAccessJwt(
	privateKey: CryptoKey,
	kid: string,
	overrides?: Record<string, unknown>,
): Promise<string> {
	const nowSec = Math.floor(Date.now() / 1000);
	const header = encodeBase64Url(
		textEncoder.encode(JSON.stringify({ alg: "RS256", typ: "JWT", kid })),
	);
	const payload = encodeBase64Url(
		textEncoder.encode(
			JSON.stringify({
				iss: `https://${TEAM_DOMAIN}`,
				aud: [ACCESS_AUD],
				exp: nowSec + 300,
				nbf: nowSec - 10,
				email: "owner@example.com",
				sub: "user-owner-1",
				...overrides,
			}),
		),
	);
	const signature = await crypto.subtle.sign(
		"RSASSA-PKCS1-v1_5",
		privateKey,
		textEncoder.encode(`${header}.${payload}`),
	);
	return `${header}.${payload}.${encodeBase64Url(new Uint8Array(signature))}`;
}

function assertStrictSecurityHeaders(response: Response): void {
	expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
	expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
	expect(response.headers.get("Permissions-Policy")).toContain("camera=()");
	expect(response.headers.get("Permissions-Policy")).toContain("microphone=()");
	expect(response.headers.get("X-Frame-Options")).toBe("DENY");
}

describe("Security hardening regression suite", () => {
	let keyPair: CryptoKeyPair;
	let publicJwk: JsonWebKey & { kid?: string; use?: string; alg?: string };
	let validJwt: string;
	const kid = "security-test-key-1";

	beforeAll(async () => {
		keyPair = (await crypto.subtle.generateKey(
			{
				name: "RSASSA-PKCS1-v1_5",
				modulusLength: 2048,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: "SHA-256",
			},
			true,
			["sign", "verify"],
		)) as CryptoKeyPair;

		publicJwk = {
			...((await crypto.subtle.exportKey("jwk", keyPair.publicKey)) as JsonWebKey),
			kid,
			use: "sig",
			alg: "RS256",
		};

		vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
			const target = typeof input === "string" ? input : input.toString();
			if (target === `https://${TEAM_DOMAIN}/cdn-cgi/access/certs`) {
				return new Response(JSON.stringify({ keys: [publicJwk] }), {
					status: 200,
					headers: { "Content-Type": "application/json" },
				});
			}
			throw new Error(`Unexpected external fetch in test: ${target}`);
		});

		validJwt = await signAccessJwt(keyPair.privateKey, kid);
	});

	afterAll(() => {
		vi.unstubAllGlobals();
	});

	describe("Dashboard API CSRF & security headers", () => {
		it("rejects POST/DELETE /dashboard/api/* requests with missing, cross-origin, same-site, or non-JSON headers", async () => {
			const { env, ctx } = createTestEnv();

			const csrfFailureCases: Array<{
				name: string;
				url: string;
				method: "POST" | "DELETE";
				headers: Record<string, string>;
				body: string;
				expectedStatus: number;
			}> = [
				{
					name: "POST allowlist missing Origin",
					url: `${BASE_URL}/dashboard/api/allowlist`,
					method: "POST",
					headers: {
						"Cf-Access-Jwt-Assertion": validJwt,
						"Content-Type": "application/json",
					},
					body: JSON.stringify({ phone: "+14155550101", status: "allowed" }),
					expectedStatus: 403,
				},
				{
					name: "POST allowlist mismatched Origin",
					url: `${BASE_URL}/dashboard/api/allowlist`,
					method: "POST",
					headers: {
						"Cf-Access-Jwt-Assertion": validJwt,
						"Content-Type": "application/json",
						Origin: "https://evil.example",
					},
					body: JSON.stringify({ phone: "+14155550101", status: "allowed" }),
					expectedStatus: 403,
				},
				{
					name: "DELETE allowlist null Origin",
					url: `${BASE_URL}/dashboard/api/allowlist`,
					method: "DELETE",
					headers: {
						"Cf-Access-Jwt-Assertion": validJwt,
						"Content-Type": "application/json",
						Origin: "null",
					},
					body: JSON.stringify({ phone: "+14155550101" }),
					expectedStatus: 403,
				},
				{
					name: "POST allowlist Sec-Fetch-Site cross-site",
					url: `${BASE_URL}/dashboard/api/allowlist`,
					method: "POST",
					headers: {
						"Cf-Access-Jwt-Assertion": validJwt,
						"Content-Type": "application/json",
						Origin: BASE_URL,
						"Sec-Fetch-Site": "cross-site",
					},
					body: JSON.stringify({ phone: "+14155550101", status: "allowed" }),
					expectedStatus: 403,
				},
				{
					name: "POST CSV Sec-Fetch-Site same-site sibling subdomain",
					url: `${BASE_URL}/dashboard/api/allowlist/csv`,
					method: "POST",
					headers: {
						"Cf-Access-Jwt-Assertion": validJwt,
						"Content-Type": "application/json",
						Origin: BASE_URL,
						"Sec-Fetch-Site": "same-site",
					},
					body: JSON.stringify({ csv: "+14155550101,Test", mode: "merge" }),
					expectedStatus: 403,
				},
				{
					name: "POST allowlist text/plain simple request bypass attempt",
					url: `${BASE_URL}/dashboard/api/allowlist`,
					method: "POST",
					headers: {
						"Cf-Access-Jwt-Assertion": validJwt,
						"Content-Type": "text/plain",
						Origin: BASE_URL,
						"Sec-Fetch-Site": "same-origin",
					},
					body: JSON.stringify({ phone: "+14155550101", status: "allowed" }),
					expectedStatus: 415,
				},
			];

			for (const testCase of csrfFailureCases) {
				const res = await worker.fetch(
					new Request(testCase.url, {
						method: testCase.method,
						headers: testCase.headers,
						body: testCase.body,
					}),
					env,
					ctx,
				);
				expect(res.status, testCase.name).toBe(testCase.expectedStatus);
				assertStrictSecurityHeaders(res);
			}

			expect(await lookupCallerRule(env.CALL_LOGS_DB, "+14155550101")).toBeNull();
		});

		it("attaches strict security headers and per-request nonce CSP across Worker responses", async () => {
			const { env, ctx } = createTestEnv();

			const htmlRes1 = await worker.fetch(
				new Request(`${BASE_URL}/dashboard`, {
					headers: { "Cf-Access-Jwt-Assertion": validJwt },
				}),
				env,
				ctx,
			);
			const htmlRes2 = await worker.fetch(
				new Request(`${BASE_URL}/dashboard`, {
					headers: { "Cf-Access-Jwt-Assertion": validJwt },
				}),
				env,
				ctx,
			);
			expect(htmlRes1.status).toBe(200);
			assertStrictSecurityHeaders(htmlRes1);

			const csp1 = htmlRes1.headers.get("Content-Security-Policy") ?? "";
			const csp2 = htmlRes2.headers.get("Content-Security-Policy") ?? "";
			expect(csp1).not.toContain("script-src 'unsafe-inline'");
			expect(csp1).toContain("base-uri 'none'");
			expect(csp1).toContain("form-action 'self'");
			expect(csp1).toContain("object-src 'none'");

			const nonceMatch1 = /script-src 'nonce-([^']+)'/.exec(csp1);
			const nonceMatch2 = /script-src 'nonce-([^']+)'/.exec(csp2);
			expect(nonceMatch1?.[1]).toBeTruthy();
			expect(nonceMatch2?.[1]).toBeTruthy();
			expect(nonceMatch1?.[1]).not.toBe(nonceMatch2?.[1]);

			const html1 = await htmlRes1.text();
			expect(html1).toContain(`<script nonce="${nonceMatch1?.[1]}">`);

			const apiRes = await worker.fetch(
				new Request(`${BASE_URL}/dashboard/api/summary`, {
					headers: { "Cf-Access-Jwt-Assertion": validJwt },
				}),
				env,
				ctx,
			);
			assertStrictSecurityHeaders(apiRes);

			const csvRes = await worker.fetch(
				new Request(`${BASE_URL}/dashboard/api/allowlist/export.csv`, {
					headers: { "Cf-Access-Jwt-Assertion": validJwt },
				}),
				env,
				ctx,
			);
			assertStrictSecurityHeaders(csvRes);

			const adminRes = await worker.fetch(
				new Request(`${BASE_URL}/admin/allowlist`, {
					method: "POST",
					headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
					body: "{}",
				}),
				env,
				ctx,
			);
			assertStrictSecurityHeaders(adminRes);

			const healthRes = await worker.fetch(new Request(`${BASE_URL}/health`), env, ctx);
			assertStrictSecurityHeaders(healthRes);
			const healthBody = (await healthRes.json()) as Record<string, unknown>;
			expect(healthBody).toEqual({ ok: true, service: "you-shall-not-ring" });
			expect("routingMode" in healthBody).toBe(false);
		});
	});

	describe("CSV formula injection, block precedence, and payload bounds", () => {
		it("neutralizes spreadsheet formula prefixes on export while keeping E.164 round-trip idempotent", async () => {
			const db = new SqliteD1Store();
			const formulaLabels = [
				{ phone: "+14155550101", label: "=SUM(1,2)" },
				{ phone: "+14155550102", label: "+1+1" },
				{ phone: "+14155550103", label: "-5" },
				{ phone: "+14155550104", label: "@SUM(A1)" },
				{ phone: "+14155550105", label: "  =1+1" },
				{ phone: "+14155550106", label: "\t=1" },
				{ phone: "+14155550107", label: "=1,2" },
			];

			for (const entry of formulaLabels.slice(0, 4)) {
				await upsertCallerRule(db, {
					phoneE164: entry.phone,
					label: entry.label,
					status: "allowed",
					source: "manual",
				});
			}

			// Simulate legacy/unstripped leading whitespace & tab rows directly in DB to verify export neutralization.
			const nowIso = new Date().toISOString();
			for (const entry of formulaLabels.slice(4)) {
				await upsertCallerRule(db, {
					phoneE164: entry.phone,
					label: "placeholder",
					status: "allowed",
					source: "manual",
				});
				db.sqlite
					.prepare("UPDATE caller_rules SET label = ?, updated_at = ? WHERE phone_e164 = ?")
					.run(entry.label, nowIso, entry.phone);
			}

			const exported = await exportCallerRulesCsv(db);
			const lines = exported.split("\r\n");
			expect(lines[0]).toBe("phone,label,status,source,expires_at");

			// Canonical E.164 phones remain unprefixed, while formula labels are single-quote escaped.
			expect(exported).toContain('+14155550101,"\'=SUM(1,2)",allowed,manual,');
			expect(exported).toContain("+14155550102,'+1+1,allowed,manual,");
			expect(exported).toContain("+14155550103,'-5,allowed,manual,");
			expect(exported).toContain("+14155550104,'@SUM(A1),allowed,manual,");
			expect(exported).toContain("+14155550105,'  =1+1,allowed,manual,");
			expect(exported).toContain("+14155550106,'\t=1,allowed,manual,");
			expect(exported).toContain('+14155550107,"\'=1,2",allowed,manual,');

			// Re-importing exported CSV stays idempotent and strips export prefix without accumulating ''.
			const parsed = parseContactsCsv(exported);
			expect(parsed.rows).toHaveLength(7);
			expect(parsed.rows.find((r) => r.phoneE164 === "+14155550101")?.label).toBe("=SUM(1,2)");

			// Overlong CSV labels are capped to 120 characters with control chars stripped.
			const longLabelCsv = `phone,label\n+14155550199,${"A".repeat(200)}\n`;
			const longParsed = parseContactsCsv(longLabelCsv);
			expect(longParsed.rows[0]?.label).toHaveLength(120);
		});

		it("prevents CSV imports (merge or replace_csv) from unblocking explicitly blocked numbers", async () => {
			const { env, ctx } = createTestEnv();
			const blockedPhone = "+14155550150";

			await upsertCallerRule(env.CALL_LOGS_DB, {
				phoneE164: blockedPhone,
				label: "Blocked Caller",
				status: "blocked",
				source: "manual",
				reason: "Persistent spammer",
				ttlSeconds: null,
			});

			const mergeRes = await importCallerRulesCsv(
				env.CALL_LOGS_DB,
				`phone,label\n${blockedPhone},Sneaky Contact\n+14155550151,Legit Friend\n`,
				"merge",
			);
			expect(mergeRes).toEqual({
				imported: 1,
				updated: 0,
				skippedInvalid: 0,
				mode: "merge",
			});

			const stillBlocked = await lookupCallerRule(env.CALL_LOGS_DB, blockedPhone);
			expect(stillBlocked?.status).toBe("blocked");
			expect(stillBlocked?.source).toBe("manual");

			// Even a blocked rule whose source was 'csv' survives replace_csv.
			await upsertCallerRule(env.CALL_LOGS_DB, {
				phoneE164: "+14155550152",
				label: "Blocked CSV",
				status: "blocked",
				source: "csv",
				ttlSeconds: null,
			});
			await importCallerRulesCsv(
				env.CALL_LOGS_DB,
				`phone,label\n+14155550152,Try Unblock\n`,
				"replace_csv",
			);
			expect((await lookupCallerRule(env.CALL_LOGS_DB, "+14155550152"))?.status).toBe("blocked");

			// Blocked caller still receives silent Hangup on /voice/incoming.
			const callRes = await worker.fetch(
				await createSignedTwilioRequest(
					`${BASE_URL}/voice/incoming`,
					{ CallSid: "CA_BLOCK_CSV_TEST", From: blockedPhone },
					env.TWILIO_AUTH_TOKEN,
				),
				env,
				ctx,
			);
			expect(await callRes.text()).toContain("<Hangup/>");
		});

		it("enforces streaming payload size caps (413) across dashboard CSV, admin sync, and voice webhooks", async () => {
			const { env, ctx } = createTestEnv();

			const hugeCsvRes = await worker.fetch(
				new Request(`${BASE_URL}/dashboard/api/allowlist/csv`, {
					method: "POST",
					headers: {
						"Cf-Access-Jwt-Assertion": validJwt,
						"Content-Type": "application/json",
						Origin: BASE_URL,
					},
					body: JSON.stringify({ csv: "a".repeat(2.6 * 1024 * 1024), mode: "merge" }),
				}),
				env,
				ctx,
			);
			expect(hugeCsvRes.status).toBe(413);

			const hugeSyncRes = await worker.fetch(
				new Request(`${BASE_URL}/admin/contacts-sync`, {
					method: "POST",
					headers: {
						Authorization: `Bearer ${env.ADMIN_TOKEN}`,
						"Content-Type": "text/plain",
					},
					body: "+14155550100\n".repeat(90_000),
				}),
				env,
				ctx,
			);
			expect(hugeSyncRes.status).toBe(413);

			const tooManyContactsRes = await worker.fetch(
				new Request(`${BASE_URL}/admin/contacts-sync`, {
					method: "POST",
					headers: {
						Authorization: `Bearer ${env.ADMIN_TOKEN}`,
						"Content-Type": "application/json",
					},
					body: JSON.stringify({
						numbers: Array.from({ length: 25_001 }, () => "+14155550100"),
					}),
				}),
				env,
				ctx,
			);
			expect(tooManyContactsRes.status).toBe(413);
		});
	});

	describe("Twilio signature, forwarding header, voicemail loop, and STIR/SHAKEN hardening", () => {
		it("ignores spoofed X-Forwarded-Host / X-Forwarded-Proto headers on HTTPS requests", async () => {
			const { env, ctx } = createTestEnv();
			const params = { CallSid: "CA_FWD_SPOOF", From: "+14155550100" };
			const spoofedUrl = "http://evil-staging.example.com/voice/incoming";
			const signatureForSpoofedHost = await computeTwilioSignature(
				spoofedUrl,
				params,
				env.TWILIO_AUTH_TOKEN,
			);

			const req = new Request(`${BASE_URL}/voice/incoming`, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					"X-Twilio-Signature": signatureForSpoofedHost,
					"X-Forwarded-Proto": "http",
					"X-Forwarded-Host": "evil-staging.example.com",
				},
				body: new URLSearchParams(params).toString(),
			});

			const res = await worker.fetch(req, env, ctx);
			expect(res.status).toBe(403);
		});

		it("rejects malformed X-Twilio-Signature headers before buffering oversized POST bodies", async () => {
			const { env, ctx } = createTestEnv();
			const malformedSigReq = new Request(`${BASE_URL}/voice/incoming`, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					"X-Twilio-Signature": "short-invalid-sig",
					"Content-Length": String(10 * 1024 * 1024),
				},
				body: "CallSid=CA1",
			});

			const res = await worker.fetch(malformedSigReq, env, ctx);
			expect(res.status).toBe(403);
		});

		it("bypasses Layer 1 trust and blocks 30-day auto-allowlisting when StirVerstat fails", async () => {
			const ai = new MockAiRunner(async () =>
				buildClefResponse({
					routingChoice: "allow",
					routingConfidence: 0.98,
					categoryChoice: "recruiter",
				}),
			);
			const { env, ctx } = createTestEnv({ AI: ai });
			const spoofedContact = "+14155550188";

			await upsertCallerRule(env.CALL_LOGS_DB, {
				phoneE164: spoofedContact,
				label: "Trusted Contact",
				status: "allowed",
				source: "manual",
			});

			// 1) Spoofed call claiming trusted number with TN-Validation-Failed-A must face Layer 2 DTMF.
			const incRes = await worker.fetch(
				await createSignedTwilioRequest(
					`${BASE_URL}/voice/incoming`,
					{
						CallSid: "CA_STIR_FAIL",
						From: spoofedContact,
						StirVerstat: "TN-Validation-Failed-A",
					},
					env.TWILIO_AUTH_TOKEN,
				),
				env,
				ctx,
			);
			const incXml = await incRes.text();
			expect(incXml).toContain('input="dtmf"');
			expect(incXml).not.toContain("<Dial");

			// 2) Even if Clef says ALLOW, a TN-Validation-Failed call must NOT overwrite rules on a new number.
			const stranger = "+14155550189";
			await worker.fetch(
				await createSignedTwilioRequest(
					`${BASE_URL}/voice/intent?attempt=1`,
					{
						CallSid: "CA_STIR_FAIL_2",
						From: stranger,
						StirVerstat: "TN-Validation-Failed-C",
						SpeechResult: "Hi, calling from recruiting about your interview.",
					},
					env.TWILIO_AUTH_TOKEN,
				),
				env,
				ctx,
			);
			expect(await lookupCallerRule(env.CALL_LOGS_DB, stranger)).toBeNull();
		});

		it("terminates voicemail <Record> via /voice/voicemail-complete and consumes whisper context once", async () => {
			const ai = new MockAiRunner(async () =>
				buildClefResponse({
					routingChoice: "uncertain",
					routingConfidence: 0.6,
					categoryChoice: "unclear",
				}),
			);
			const { env, ctx } = createTestEnv({ AI: ai });

			const dialCompleteRes = await worker.fetch(
				await createSignedTwilioRequest(
					`${BASE_URL}/voice/dial-complete`,
					{
						CallSid: "CA_VM_TEST",
						From: "+14155550177",
						DialCallStatus: "no-answer",
					},
					env.TWILIO_AUTH_TOKEN,
				),
				env,
				ctx,
			);
			const vmXml = await dialCompleteRes.text();
			expect(vmXml).toContain(`action="${BASE_URL}/voice/voicemail-complete"`);
			expect(vmXml).toContain("<Hangup/>");

			const vmCompleteRes = await worker.fetch(
				await createSignedTwilioRequest(
					`${BASE_URL}/voice/voicemail-complete`,
					{
						CallSid: "CA_VM_TEST",
						RecordingSid: "RE123",
					},
					env.TWILIO_AUTH_TOKEN,
				),
				env,
				ctx,
			);
			expect(await vmCompleteRes.text()).toContain("<Hangup/>");

			// UNCERTAIN call saves whisper context, and /voice/whisper-action consumes it once.
			const caller = "+14155550166";
			await worker.fetch(
				await createSignedTwilioRequest(
					`${BASE_URL}/voice/intent?attempt=1`,
					{
						CallSid: "CA_WHISPER_ONCE",
						From: caller,
						SpeechResult: "Hey, please press 1 to hear my message.",
					},
					env.TWILIO_AUTH_TOKEN,
				),
				env,
				ctx,
			);

			const whisperPromptRes = await worker.fetch(
				await createSignedTwilioRequest(
					`${BASE_URL}/voice/whisper?sid=CA_WHISPER_ONCE`,
					{ CallSid: "CA_CHILD_W", ParentCallSid: "CA_WHISPER_ONCE" },
					env.TWILIO_AUTH_TOKEN,
				),
				env,
				ctx,
			);
			const whisperXml = await whisperPromptRes.text();
			expect(whisperXml).toContain("[redacted]");
			expect(whisperXml).toContain("End of caller note.");

			await worker.fetch(
				await createSignedTwilioRequest(
					`${BASE_URL}/voice/whisper-action?sid=CA_WHISPER_ONCE`,
					{ CallSid: "CA_CHILD_W", Digits: "1" },
					env.TWILIO_AUTH_TOKEN,
				),
				env,
				ctx,
			);
			expect((await lookupCallerRule(env.CALL_LOGS_DB, caller))?.status).toBe("allowed");

			// Replaying Press 2 on the already-consumed whisper context must NOT mutate the rule.
			await worker.fetch(
				await createSignedTwilioRequest(
					`${BASE_URL}/voice/whisper-action?sid=CA_WHISPER_ONCE`,
					{ CallSid: "CA_CHILD_W", Digits: "2" },
					env.TWILIO_AUTH_TOKEN,
				),
				env,
				ctx,
			);
			expect((await lookupCallerRule(env.CALL_LOGS_DB, caller))?.status).toBe("allowed");
		});
	});

	describe("Clef guardrails & Cloudflare Access JWT edge cases", () => {
		it("fails closed on missing/elevated prompt_injection scores, truncates >600 chars consistently, and avoids fallback auto-allow", async () => {
			const missingInjectionAi = new MockAiRunner(async () => ({
				model: "clef",
				answers: {
					routing: {
						type: "choice",
						choice: "allow",
						probabilities: { allow: 0.99 },
						confidence: 0.99,
					},
					category: {
						type: "choice",
						choice: "personal",
						probabilities: { personal: 0.9 },
						confidence: 0.9,
					},
				},
			}));
			const { env: missingEnv } = createTestEnv({ AI: missingInjectionAi });
			const missingRes = await classifyCallerIntent(missingEnv, "Hey, calling to catch up.");
			expect(missingRes.decision).toBe("UNCERTAIN");

			const greyZoneAi = new MockAiRunner(async () =>
				buildClefResponse({
					routingChoice: "allow",
					routingConfidence: 0.95,
					categoryChoice: "recruiter",
					injectionScore: 0.45,
				}),
			);
			const { env: greyEnv } = createTestEnv({ AI: greyZoneAi });
			const greyRes = await classifyCallerIntent(greyEnv, "Calling about a role.");
			expect(greyRes.decision).toBe("UNCERTAIN");
			expect(greyRes.promptInjectionScore).toBe(0.45);

			// >600 char transcript truncation parity: trailing keyword after 600 chars does not trigger fallback.
			const failingAi = new MockAiRunner(async () => {
				throw new Error("AI unavailable");
			});
			const { env: failEnv } = createTestEnv({ AI: failingAi });
			const longSpeech = `${"Hello there. ".repeat(55)}loan pre-approved`;
			const truncatedFallback = await classifyCallerIntent(failEnv, longSpeech);
			expect(truncatedFallback.decision).toBe("UNCERTAIN");
			expect(truncatedFallback.category).toBe("unclear");
			expect(truncatedFallback.fromFallback).toBe(true);

			// Spoken "press 1" / "press 2" is redacted in whisper summaries.
			expect(sanitizeWhisperSummary("Please press 1 or press two now")).toBe(
				"Please [redacted] or [redacted] now",
			);
		});

		it("throttles repeated unknown-kid JWKS refreshes and handles shadowed CF_Authorization cookies", async () => {
			const { env } = createTestEnv({
				CF_ACCESS_TEAM_DOMAIN: TEAM_DOMAIN,
				CF_ACCESS_AUD: ACCESS_AUD,
			});

			let fetchCount = 0;
			const isolatedFetcher: typeof fetch = async () => {
				fetchCount += 1;
				return new Response(JSON.stringify({ keys: [publicJwk] }), { status: 200 });
			};

			// First request caches initial JWKS (fetch #1).
			const validRes = await verifyCloudflareAccessRequest(
				new Request(`${BASE_URL}/dashboard`, {
					headers: { "Cf-Access-Jwt-Assertion": validJwt },
				}),
				env,
				isolatedFetcher,
			);
			expect(validRes.ok).toBe(true);
			expect(fetchCount).toBe(1);

			// First unknown kid triggers one rotation check (fetch #2).
			const unknownJwt1 = await signAccessJwt(keyPair.privateKey, "unknown-kid-1");
			const unknownRes1 = await verifyCloudflareAccessRequest(
				new Request(`${BASE_URL}/dashboard`, {
					headers: { "Cf-Access-Jwt-Assertion": unknownJwt1 },
				}),
				env,
				isolatedFetcher,
			);
			expect(unknownRes1.ok).toBe(false);
			expect(fetchCount).toBe(2);

			// Repeated unknown kids within the 30s cooldown do NOT trigger extra JWKS fetches.
			const unknownJwt2 = await signAccessJwt(keyPair.privateKey, "unknown-kid-2");
			const unknownRes2 = await verifyCloudflareAccessRequest(
				new Request(`${BASE_URL}/dashboard`, {
					headers: { "Cf-Access-Jwt-Assertion": unknownJwt2 },
				}),
				env,
				isolatedFetcher,
			);
			expect(unknownRes2.ok).toBe(false);
			expect(fetchCount).toBe(2);

			// Stale/expired CF_Authorization cookie before a valid CF_Authorization cookie still succeeds.
			const expiredJwt = await signAccessJwt(keyPair.privateKey, kid, {
				exp: Math.floor(Date.now() / 1000) - 600,
			});
			const multiCookieReq = new Request(`${BASE_URL}/dashboard`, {
				headers: {
					Cookie: `CF_Authorization=${expiredJwt}; CF_Authorization=${validJwt}`,
				},
			});
			const multiCookieRes = await verifyCloudflareAccessRequest(
				multiCookieReq,
				env,
				isolatedFetcher,
			);
			expect(multiCookieRes).toEqual({
				ok: true,
				identity: { email: "owner@example.com", sub: "user-owner-1" },
			});
		});

		it("rejects invalid CF_ACCESS_TEAM_DOMAIN configurations with 503", async () => {
			const { env } = createTestEnv({
				CF_ACCESS_TEAM_DOMAIN: "evil.example.com/path?x=1",
				CF_ACCESS_AUD: ACCESS_AUD,
			});
			const res = await verifyCloudflareAccessRequest(
				new Request(`${BASE_URL}/dashboard`, {
					headers: { "Cf-Access-Jwt-Assertion": validJwt },
				}),
				env,
			);
			expect(res.ok).toBe(false);
			if (!res.ok) {
				expect(res.status).toBe(503);
			}
		});
	});
});
