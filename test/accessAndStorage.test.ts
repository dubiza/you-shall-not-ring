import { beforeAll, describe, expect, it } from "vitest";
import { verifyCloudflareAccessRequest } from "../src/security/cloudflareAccess.ts";
import {
	calculateCallCostCents,
	ensureSchema,
	finalizeCallStatus,
	getDashboardSummary,
	listCallLogs,
	pruneExpiredCallLogs,
	updateCallProgress,
	upsertCallStart,
} from "../src/storage/callLogs.ts";
import {
	deleteCallerRule,
	exportCallerRulesCsv,
	importCallerRulesCsv,
	listCallerRules,
	lookupCallerRule,
	parseContactsCsv,
	upsertCallerRule,
} from "../src/storage/callerRules.ts";
import { createTestEnv, SqliteD1Store } from "./helpers/mockEnv.ts";

const textEncoder = new TextEncoder();

function encodeBase64Url(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function encodeJsonBase64Url(value: unknown): string {
	return encodeBase64Url(textEncoder.encode(JSON.stringify(value)));
}

async function signJwt(
	privateKey: CryptoKey,
	header: Record<string, unknown>,
	payload: Record<string, unknown>,
): Promise<string> {
	const headerSegment = encodeJsonBase64Url(header);
	const payloadSegment = encodeJsonBase64Url(payload);
	const signingInput = textEncoder.encode(`${headerSegment}.${payloadSegment}`);
	const sigBuffer = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, signingInput);
	const signatureSegment = encodeBase64Url(new Uint8Array(sigBuffer));
	return `${headerSegment}.${payloadSegment}.${signatureSegment}`;
}

describe("Cloudflare Zero Trust Access JWT verification", () => {
	let keyPairA: CryptoKeyPair;
	let publicJwkA: JsonWebKey & { kid?: string; use?: string; alg?: string };
	let keyPairB: CryptoKeyPair;
	let publicJwkB: JsonWebKey & { kid?: string; use?: string; alg?: string };

	beforeAll(async () => {
		keyPairA = (await crypto.subtle.generateKey(
			{
				name: "RSASSA-PKCS1-v1_5",
				modulusLength: 2048,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: "SHA-256",
			},
			true,
			["sign", "verify"],
		)) as CryptoKeyPair;
		publicJwkA = {
			...((await crypto.subtle.exportKey("jwk", keyPairA.publicKey)) as JsonWebKey),
			kid: "kid-primary-1",
			use: "sig",
			alg: "RS256",
		};

		keyPairB = (await crypto.subtle.generateKey(
			{
				name: "RSASSA-PKCS1-v1_5",
				modulusLength: 2048,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: "SHA-256",
			},
			true,
			["sign", "verify"],
		)) as CryptoKeyPair;
		publicJwkB = {
			...((await crypto.subtle.exportKey("jwk", keyPairB.publicKey)) as JsonWebKey),
			kid: "kid-rotated-2",
			use: "sig",
			alg: "RS256",
		};
	});

	it("accepts a valid RS256 JWT from header or CF_Authorization cookie and caches JWKS", async () => {
		const { env } = createTestEnv({
			CF_ACCESS_TEAM_DOMAIN: "https://firewall-test.cloudflareaccess.com/",
			CF_ACCESS_AUD: "aud-tag-xyz",
		});

		let fetchCount = 0;
		const fetcher: typeof fetch = async (input) => {
			fetchCount += 1;
			expect(String(input)).toBe("https://firewall-test.cloudflareaccess.com/cdn-cgi/access/certs");
			return new Response(JSON.stringify({ keys: [publicJwkA] }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		};

		const nowSec = Math.floor(Date.now() / 1000);
		const jwt = await signJwt(
			keyPairA.privateKey,
			{ alg: "RS256", kid: "kid-primary-1", typ: "JWT" },
			{
				iss: "https://firewall-test.cloudflareaccess.com",
				aud: ["aud-tag-xyz"],
				exp: nowSec + 300,
				nbf: nowSec - 10,
				email: "owner@example.com",
				sub: "user-sub-123",
			},
		);

		const headerReq = new Request("https://worker.example.com/dashboard", {
			headers: { "Cf-Access-Jwt-Assertion": jwt },
		});
		const res1 = await verifyCloudflareAccessRequest(headerReq, env, fetcher);
		expect(res1).toEqual({
			ok: true,
			identity: { email: "owner@example.com", sub: "user-sub-123" },
		});
		expect(fetchCount).toBe(1);

		const cookieReq = new Request("https://worker.example.com/dashboard/api/summary", {
			headers: { Cookie: `other=abc; CF_Authorization=${jwt}; theme=dark` },
		});
		const res2 = await verifyCloudflareAccessRequest(cookieReq, env, fetcher);
		expect(res2).toEqual({
			ok: true,
			identity: { email: "owner@example.com", sub: "user-sub-123" },
		});
		// Cached JWKS should be reused without a second network fetch.
		expect(fetchCount).toBe(1);
	});

	it("refreshes JWKS once on an unknown kid", async () => {
		const { env } = createTestEnv({
			CF_ACCESS_TEAM_DOMAIN: "firewall-test.cloudflareaccess.com",
			CF_ACCESS_AUD: "aud-rotate",
		});

		let fetchCount = 0;
		const fetcher: typeof fetch = async () => {
			fetchCount += 1;
			const keys = fetchCount === 1 ? [publicJwkA] : [publicJwkA, publicJwkB];
			return new Response(JSON.stringify({ keys }), { status: 200 });
		};

		const nowSec = Math.floor(Date.now() / 1000);
		const tokenA = await signJwt(
			keyPairA.privateKey,
			{ alg: "RS256", kid: "kid-primary-1" },
			{
				iss: "https://firewall-test.cloudflareaccess.com",
				aud: "aud-rotate",
				exp: nowSec + 300,
				email: "a@example.com",
				sub: "sub-a",
			},
		);
		const tokenB = await signJwt(
			keyPairB.privateKey,
			{ alg: "RS256", kid: "kid-rotated-2" },
			{
				iss: "https://firewall-test.cloudflareaccess.com",
				aud: "aud-rotate",
				exp: nowSec + 300,
				email: "b@example.com",
				sub: "sub-b",
			},
		);

		expect(
			(
				await verifyCloudflareAccessRequest(
					new Request("https://w.example.com/dashboard", {
						headers: { "Cf-Access-Jwt-Assertion": tokenA },
					}),
					env,
					fetcher,
				)
			).ok,
		).toBe(true);
		expect(fetchCount).toBe(1);

		const resB = await verifyCloudflareAccessRequest(
			new Request("https://w.example.com/dashboard", {
				headers: { "Cf-Access-Jwt-Assertion": tokenB },
			}),
			env,
			fetcher,
		);
		expect(resB).toEqual({
			ok: true,
			identity: { email: "b@example.com", sub: "sub-b" },
		});
		expect(fetchCount).toBe(2);
	});

	it("rejects expired, wrong-aud, wrong-iss, future-nbf, and tampered JWTs with 403", async () => {
		const { env } = createTestEnv({
			CF_ACCESS_TEAM_DOMAIN: "firewall-test.cloudflareaccess.com",
			CF_ACCESS_AUD: "expected-aud",
		});

		const fetcher: typeof fetch = async () =>
			new Response(JSON.stringify({ keys: [publicJwkA] }), { status: 200 });

		const nowSec = Math.floor(Date.now() / 1000);
		const baseHeader = { alg: "RS256", kid: "kid-primary-1" };

		const expiredJwt = await signJwt(keyPairA.privateKey, baseHeader, {
			iss: "https://firewall-test.cloudflareaccess.com",
			aud: ["expected-aud"],
			exp: nowSec - 120,
			email: "owner@example.com",
			sub: "sub-1",
		});
		const expiredRes = await verifyCloudflareAccessRequest(
			new Request("https://w.example.com/dashboard", {
				headers: { "Cf-Access-Jwt-Assertion": expiredJwt },
			}),
			env,
			fetcher,
		);
		expect(expiredRes.ok).toBe(false);
		if (!expiredRes.ok) {
			expect(expiredRes.status).toBe(403);
		}

		const wrongAudJwt = await signJwt(keyPairA.privateKey, baseHeader, {
			iss: "https://firewall-test.cloudflareaccess.com",
			aud: ["different-aud"],
			exp: nowSec + 300,
			email: "owner@example.com",
			sub: "sub-1",
		});
		const wrongAudRes = await verifyCloudflareAccessRequest(
			new Request("https://w.example.com/dashboard", {
				headers: { "Cf-Access-Jwt-Assertion": wrongAudJwt },
			}),
			env,
			fetcher,
		);
		expect(wrongAudRes.ok).toBe(false);
		if (!wrongAudRes.ok) {
			expect(wrongAudRes.status).toBe(403);
		}

		const futureNbfJwt = await signJwt(keyPairA.privateKey, baseHeader, {
			iss: "https://firewall-test.cloudflareaccess.com",
			aud: ["expected-aud"],
			nbf: nowSec + 120,
			exp: nowSec + 600,
			email: "owner@example.com",
			sub: "sub-1",
		});
		const nbfRes = await verifyCloudflareAccessRequest(
			new Request("https://w.example.com/dashboard", {
				headers: { "Cf-Access-Jwt-Assertion": futureNbfJwt },
			}),
			env,
			fetcher,
		);
		expect(nbfRes.ok).toBe(false);
		if (!nbfRes.ok) {
			expect(nbfRes.status).toBe(403);
		}

		const wrongIssJwt = await signJwt(keyPairA.privateKey, baseHeader, {
			iss: "https://evil-team.cloudflareaccess.com",
			aud: ["expected-aud"],
			exp: nowSec + 300,
			email: "owner@example.com",
			sub: "sub-1",
		});
		const issRes = await verifyCloudflareAccessRequest(
			new Request("https://w.example.com/dashboard", {
				headers: { "Cf-Access-Jwt-Assertion": wrongIssJwt },
			}),
			env,
			fetcher,
		);
		expect(issRes.ok).toBe(false);
		if (!issRes.ok) {
			expect(issRes.status).toBe(403);
		}

		const validJwt = await signJwt(keyPairA.privateKey, baseHeader, {
			iss: "https://firewall-test.cloudflareaccess.com",
			aud: ["expected-aud"],
			exp: nowSec + 300,
			email: "owner@example.com",
			sub: "sub-1",
		});
		const parts = validJwt.split(".");
		const tamperedPayload = encodeJsonBase64Url({
			iss: "https://firewall-test.cloudflareaccess.com",
			aud: ["expected-aud"],
			exp: nowSec + 300,
			email: "attacker@example.com",
			sub: "sub-1",
		});
		const tamperedJwt = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
		const tamperedRes = await verifyCloudflareAccessRequest(
			new Request("https://w.example.com/dashboard", {
				headers: { "Cf-Access-Jwt-Assertion": tamperedJwt },
			}),
			env,
			fetcher,
		);
		expect(tamperedRes.ok).toBe(false);
		if (!tamperedRes.ok) {
			expect(tamperedRes.status).toBe(403);
		}
	});

	it("returns 401 when token is missing and 503 when Access config is missing", async () => {
		const { env } = createTestEnv();
		const missingTokenRes = await verifyCloudflareAccessRequest(
			new Request("https://w.example.com/dashboard"),
			env,
		);
		expect(missingTokenRes.ok).toBe(false);
		if (!missingTokenRes.ok) {
			expect(missingTokenRes.status).toBe(401);
		}

		const { env: unconfiguredEnv } = createTestEnv({
			CF_ACCESS_TEAM_DOMAIN: "   ",
			CF_ACCESS_AUD: "",
		});
		const unconfiguredRes = await verifyCloudflareAccessRequest(
			new Request("https://w.example.com/dashboard", {
				headers: { "Cf-Access-Jwt-Assertion": "a.b.c" },
			}),
			unconfiguredEnv,
		);
		expect(unconfiguredRes.ok).toBe(false);
		if (!unconfiguredRes.ok) {
			expect(unconfiguredRes.status).toBe(503);
		}
	});
});

describe("callerRules storage and contacts CSV parsing/import/export", () => {
	it("parses RFC-4180 CSV, 1-column lists, Google/Apple headers, and deduplicates keeping latest label", () => {
		const simple = parseContactsCsv(
			"\uFEFF(415) 555-0100\r\n1-415-555-0101,Dr. Smith\r\nanonymous,Ignored\r\n+14155550101,Dr. Alice Smith\r\n+14155550101,\r\n",
		);
		expect(simple.skippedInvalid).toBe(1);
		expect(simple.rows).toEqual([
			{ phoneE164: "+14155550100", label: "" },
			{ phoneE164: "+14155550101", label: "Dr. Alice Smith" },
		]);

		const googleAppleCsv = [
			'First Name,Last Name,Phone 1 - Type,Phone 1 - Value,Phone 2 - Value',
			'Jane,"Doe, MD",Mobile,"(415) 555-0188",',
			'Bob,Builder,Work,+1 650-555-0199,invalid-phone',
			',,Home,restricted,',
		].join("\r\n");

		const parsed = parseContactsCsv(googleAppleCsv);
		expect(parsed.skippedInvalid).toBe(2);
		expect(parsed.rows).toEqual([
			{ phoneE164: "+14155550188", label: "Jane Doe, MD" },
			{ phoneE164: "+16505550199", label: "Bob Builder" },
		]);

		const quotedCsv = [
			'phone,label',
			'"+14155550123","Acme ""VIP"" Support"',
		].join("\n");
		const parsedQuoted = parseContactsCsv(quotedCsv);
		expect(parsedQuoted.rows).toEqual([
			{ phoneE164: "+14155550123", label: 'Acme "VIP" Support' },
		]);
	});

	it("supports chunked >25-row CSV import, merge vs replace_csv, TTL rules, and CSV export round-trip", async () => {
		const db = new SqliteD1Store(false);

		// Add a manual rule that must survive replace_csv mode.
		await upsertCallerRule(db, {
			phoneE164: "+14155559999",
			label: "Manual VIP",
			status: "allowed",
			source: "manual",
			reason: "Manually pinned",
			ttlSeconds: null,
		});

		// Add an expired rule that must not show up in lookup or list/export.
		await upsertCallerRule(db, {
			phoneE164: "+14155558888",
			label: "Expired Rule",
			status: "allowed",
			source: "auto_clef",
			ttlSeconds: 1,
		});
		db.sqlite
			.prepare("UPDATE caller_rules SET expires_at = ? WHERE phone_e164 = ?")
			.run("2020-01-01T00:00:00.000Z", "+14155558888");
		expect(await lookupCallerRule(db, "+14155558888")).toBeNull();

		// Import 27 CSV rows (> 2 chunks of 10 rows) to test multi-row D1 parameter cap chunking.
		const csvLines = ["phone,label"];
		for (let i = 0; i < 27; i += 1) {
			const suffix = String(1000 + i);
			csvLines.push(`+1415555${suffix},Contact ${i}`);
		}
		csvLines.push("bad-row,Should Skip");

		const firstImport = await importCallerRulesCsv(db, csvLines.join("\n"), "merge");
		expect(firstImport).toEqual({
			imported: 27,
			updated: 0,
			skippedInvalid: 1,
			mode: "merge",
		});

		// Merge update: 2 existing rows updated (1 with empty label preserving existing label) + 1 new row.
		const mergeCsv = [
			"phone,label",
			"+14155551000,",
			"+14155551001,Contact 1 Updated",
			"+14155552000,Brand New Contact",
		].join("\n");
		const mergeResult = await importCallerRulesCsv(db, mergeCsv, "merge");
		expect(mergeResult).toEqual({
			imported: 1,
			updated: 2,
			skippedInvalid: 0,
			mode: "merge",
		});

		const preservedRule = await lookupCallerRule(db, "+14155551000");
		expect(preservedRule?.label).toBe("Contact 0");
		const updatedRule = await lookupCallerRule(db, "+14155551001");
		expect(updatedRule?.label).toBe("Contact 1 Updated");

		// Omitting label on upsertCallerRule preserves existing non-empty label.
		const blockedPreservingLabel = await upsertCallerRule(db, {
			phoneE164: "+14155551001",
			status: "blocked",
			source: "whisper_block",
			reason: "Blocked via Press 2",
			ttlSeconds: null,
		});
		expect(blockedPreservingLabel.label).toBe("Contact 1 Updated");
		expect(blockedPreservingLabel.status).toBe("blocked");

		// replace_csv deletes prior source='csv' rows while keeping manual/whisper rules.
		const replaceCsv = "phone,label\n+14155553000,Fresh CSV Contact\n";
		const replaceResult = await importCallerRulesCsv(db, replaceCsv, "replace_csv");
		expect(replaceResult).toEqual({
			imported: 1,
			updated: 0,
			skippedInvalid: 0,
			mode: "replace_csv",
		});

		expect(await lookupCallerRule(db, "+14155551000")).toBeNull();
		expect((await lookupCallerRule(db, "+14155559999"))?.label).toBe("Manual VIP");
		expect((await lookupCallerRule(db, "+14155551001"))?.source).toBe("whisper_block");

		// Export CSV round-trip excludes expired rule and re-parses cleanly.
		const exported = await exportCallerRulesCsv(db);
		expect(exported.split(/\r?\n/)[0]).toBe("phone,label,status,source,expires_at");
		expect(exported).not.toContain("+14155558888");
		const reParsed = parseContactsCsv(exported);
		expect(reParsed.rows).toHaveLength(3);
		expect(reParsed.rows.find((r) => r.phoneE164 === "+14155559999")?.label).toBe("Manual VIP");

		const activeRules = await listCallerRules(db, { status: "allowed", search: "Fresh" });
		expect(activeRules).toHaveLength(1);
		expect(activeRules[0]?.phone_e164).toBe("+14155553000");

		expect(await deleteCallerRule(db, "+14155553000")).toBe(true);
		expect(await deleteCallerRule(db, "+14155553000")).toBe(false);
	});
});

describe("callLogs lifecycle, cost math, dashboard summary, and 90-day pruning", () => {
	it("computes Twilio cost cents accurately", () => {
		expect(
			calculateCallCostCents({ inboundDurationSec: 0, sipDurationSec: 0, speechAttempts: 0 }),
		).toBe(0);
		// 61s inbound -> ceil(61/60)=2 * 0.85 = 1.70; 30s SIP -> 1 * 0.40 = 0.40; 2 speech -> 4.00 => 6.10
		expect(
			calculateCallCostCents({ inboundDurationSec: 61, sipDurationSec: 30, speechAttempts: 2 }),
		).toBe(6.1);
	});

	it("initializes schema idempotently, tracks progress, finalizes abandoned calls, aggregates summary, lists with callerLabel, and prunes >90d rows", async () => {
		const db = new SqliteD1Store(false);
		await ensureSchema(db);
		await ensureSchema(db); // Second call hits WeakSet cache cleanly.

		await upsertCallerRule(db, {
			phoneE164: "+14155550111",
			label: "Alice Recruiter",
			status: "allowed",
			source: "manual",
		});

		// 1. Call that advances through DTMF -> Speech -> Clef ALLOW -> SIP bridged.
		await upsertCallStart(db, {
			callSid: "CA_ALLOW_1",
			fromNumber: "+14155550111",
			callerTrust: "unknown",
			furthestPhase: "L2_DTMF",
			finalOutcome: "IN_PROGRESS",
			expectedDigit: "4",
			outcomeReason: "Awaiting keypad verification",
		});
		await updateCallProgress(db, "CA_ALLOW_1", {
			furthestPhase: "L3_SPEECH",
			pressedDigit: "4",
		});
		await updateCallProgress(db, "CA_ALLOW_1", {
			furthestPhase: "BRIDGED",
			finalOutcome: "CONNECTED_AI_ALLOW",
			speechAttemptsIncrement: 1,
			transcript: "Hi Siobhan, calling about the engineering role",
			aiDecision: "ALLOW",
			aiCategory: "recruiter",
			aiConfidence: 0.94,
			promptInjectionScore: 0.02,
			outcomeReason: "Legitimate recruiter",
		});
		await updateCallProgress(db, "CA_ALLOW_1", { sipDurationSec: 95 });
		await finalizeCallStatus(db, {
			callSid: "CA_ALLOW_1",
			fromNumber: "+14155550111",
			inboundDurationSec: 120,
			callStatus: "completed",
		});

		const allowRow = await db
			.prepare("SELECT * FROM call_logs WHERE call_sid = ?")
			.bind("CA_ALLOW_1")
			.first<Record<string, unknown>>();
		expect(allowRow?.final_outcome).toBe("CONNECTED_AI_ALLOW");
		expect(allowRow?.pressed_digit).toBe("4");
		expect(allowRow?.speech_attempts).toBe(1);
		expect(allowRow?.sip_duration_sec).toBe(95);
		expect(allowRow?.inbound_duration_sec).toBe(120);
		// 120s inbound (2*0.85=1.70) + 95s sip (2*0.40=0.80) + 1 speech (2.00) = 4.50
		expect(allowRow?.estimated_cost_cents).toBe(4.5);

		// 2. Abandoned IN_PROGRESS calls at L2_DTMF, L3_SPEECH, WHISPER, and BRIDGED.
		await upsertCallStart(db, {
			callSid: "CA_ABANDON_L2",
			fromNumber: "+14155550222",
			callerTrust: "unknown",
			furthestPhase: "L2_DTMF",
			finalOutcome: "IN_PROGRESS",
			expectedDigit: "7",
		});
		await finalizeCallStatus(db, {
			callSid: "CA_ABANDON_L2",
			fromNumber: "+14155550222",
			inboundDurationSec: 12,
			callStatus: "completed",
		});

		await upsertCallStart(db, {
			callSid: "CA_ABANDON_L3",
			fromNumber: "+14155550333",
			callerTrust: "unknown",
			furthestPhase: "L3_SPEECH",
			finalOutcome: "IN_PROGRESS",
		});
		await finalizeCallStatus(db, {
			callSid: "CA_ABANDON_L3",
			fromNumber: "+14155550333",
			inboundDurationSec: 20,
			callStatus: "no-answer",
		});

		await upsertCallStart(db, {
			callSid: "CA_ABANDON_WHISPER",
			fromNumber: "+14155550444",
			callerTrust: "unknown",
			furthestPhase: "WHISPER",
			finalOutcome: "IN_PROGRESS",
		});
		await finalizeCallStatus(db, {
			callSid: "CA_ABANDON_WHISPER",
			fromNumber: "+14155550444",
			inboundDurationSec: 30,
			callStatus: "completed",
		});

		await upsertCallStart(db, {
			callSid: "CA_ABANDON_BRIDGED",
			fromNumber: "+14155550555",
			callerTrust: "contact",
			furthestPhase: "BRIDGED",
			finalOutcome: "IN_PROGRESS",
		});
		await finalizeCallStatus(db, {
			callSid: "CA_ABANDON_BRIDGED",
			fromNumber: "+14155550555",
			inboundDurationSec: 45,
			callStatus: "completed",
		});

		// 3. Spam blocked at L3 AI & L1 Blocked & L2 Wrong.
		await upsertCallStart(db, {
			callSid: "CA_L1_BLOCK",
			fromNumber: "+14155550666",
			callerTrust: "blocked",
			furthestPhase: "L1_ALLOWLIST",
			finalOutcome: "BLOCKED_L1",
		});

		await upsertCallStart(db, {
			callSid: "CA_L3_SPAM",
			fromNumber: "+14155550777",
			callerTrust: "unknown",
			furthestPhase: "L3_CLEF",
			finalOutcome: "STOPPED_L3_AI_SPAM",
		});
		await updateCallProgress(db, "CA_L3_SPAM", {
			aiCategory: "loan_scam",
			speechAttemptsIncrement: 1,
		});

		// 4. Old row (> 90 days) to test pruning.
		await upsertCallStart(db, {
			callSid: "CA_OLD_95D",
			fromNumber: "+14155550888",
			callerTrust: "unknown",
			furthestPhase: "L2_DTMF",
			finalOutcome: "STOPPED_L2_DTMF_WRONG",
		});
		const oldIso = new Date(Date.now() - 95 * 86_400_000).toISOString();
		db.sqlite.prepare("UPDATE call_logs SET started_at = ? WHERE call_sid = ?").run(oldIso, "CA_OLD_95D");

		// Before pruning, 7d summary excludes CA_OLD_95D and uses fixedNumberCostCents = 27.
		const summary7d = await getDashboardSummary(db, "7d");
		expect(summary7d.fixedNumberCostCents).toBe(27);
		expect(summary7d.totalCalls).toBe(7);
		expect(summary7d.stoppedAtL1Blocked).toBe(1);
		expect(summary7d.stoppedAtL2Abandoned).toBe(1);
		expect(summary7d.stoppedAtL3Silence).toBe(1);
		expect(summary7d.stoppedAtL3AiSpam).toBe(1);
		expect(summary7d.rejectedAtWhisper).toBe(1);
		expect(summary7d.spamStoppedCount).toBe(5);
		expect(summary7d.spamStoppedPct).toBe(71.4);
		expect(summary7d.reachedUserCount).toBe(2);
		expect(summary7d.totalEstimatedCostCents).toBe(
			Math.round((summary7d.usageCostCents + 27) * 100) / 100,
		);
		expect(summary7d.categoryBreakdown.some((c) => c.category === "loan_scam" && c.count === 1)).toBe(true);

		const summary30d = await getDashboardSummary(db, "30d");
		expect(summary30d.fixedNumberCostCents).toBe(115);

		// listCallLogs joins caller_rules.label and supports filtering & clamping.
		const filtered = await listCallLogs(db, {
			search: "Alice Recruiter",
			limit: 500,
			offset: -5,
		});
		expect(filtered.total).toBe(1);
		expect(filtered.items[0]?.call_sid).toBe("CA_ALLOW_1");
		expect(filtered.items[0]?.callerLabel).toBe("Alice Recruiter");

		// Prune >90d logs.
		await pruneExpiredCallLogs(db, 90);
		const allAfterPrune = await listCallLogs(db, { period: "all" });
		expect(allAfterPrune.total).toBe(7);
		expect(allAfterPrune.items.some((item) => item.call_sid === "CA_OLD_95D")).toBe(false);
	});
});
