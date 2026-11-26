import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import worker from "../src/index.ts";
import type { CallLogRow, CallerRuleRow, DashboardSummary } from "../src/types.ts";
import {
	buildClefResponse,
	createSignedTwilioRequest,
	createTestEnv,
	MockAiRunner,
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

describe("Dashboard Zero Trust Access, call funnel telemetry, and CSV allowlist", () => {
	let keyPair: CryptoKeyPair;
	let validJwt: string;
	const kid = "dashboard-test-key-1";

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

		const publicJwk = {
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

	it("enforces Cloudflare Zero Trust Access JWT on HTML and API routes and renders modern UI", async () => {
		const { env, ctx } = createTestEnv();

		const noHeaderHtml = await worker.fetch(new Request(`${BASE_URL}/dashboard`), env, ctx);
		expect(noHeaderHtml.status).toBe(401);
		expect(noHeaderHtml.headers.get("Content-Type")).toContain("text/html");

		const noHeaderApi = await worker.fetch(
			new Request(`${BASE_URL}/dashboard/api/summary`),
			env,
			ctx,
		);
		expect(noHeaderApi.status).toBe(401);
		expect(noHeaderApi.headers.get("Content-Type")).toContain("application/json");

		const badAudJwt = await signAccessJwt(keyPair.privateKey, kid, { aud: ["wrong-aud"] });
		const badAudRes = await worker.fetch(
			new Request(`${BASE_URL}/dashboard/api/summary`, {
				headers: { "Cf-Access-Jwt-Assertion": badAudJwt },
			}),
			env,
			ctx,
		);
		expect(badAudRes.status).toBe(403);

		const unconfiguredRes = await worker.fetch(
			new Request(`${BASE_URL}/dashboard/api/summary`, {
				headers: { "Cf-Access-Jwt-Assertion": validJwt },
			}),
			{ ...env, CF_ACCESS_AUD: "" },
			ctx,
		);
		expect(unconfiguredRes.status).toBe(503);

		const htmlRes = await worker.fetch(
			new Request(`${BASE_URL}/dashboard`, {
				headers: { "Cf-Access-Jwt-Assertion": validJwt },
			}),
			env,
			ctx,
		);
		expect(htmlRes.status).toBe(200);
		expect(htmlRes.headers.get("Content-Security-Policy")).toContain("default-src 'self'");
		const html = await htmlRes.text();
		expect(html).toContain('<meta name="color-scheme" content="light dark">');
		expect(html).toContain('focusgroup="tablist nomemory"');
		expect(html).toContain('closedby="any"');
		expect(html).toContain("owner@example.com");
	});

	it("tracks full call funnel phases, abandoned calls, and penny-accurate Twilio spend", async () => {
		const ai = new MockAiRunner(async (_model, inputs) => {
			const state = String(inputs.state ?? "");
			if (state.includes("Stripe")) {
				return buildClefResponse({
					routingChoice: "allow",
					routingConfidence: 0.95,
					categoryChoice: "recruiter",
				});
			}
			return buildClefResponse({
				routingChoice: "spam",
				routingConfidence: 0.92,
				categoryChoice: "loan_scam",
			});
		});

		const { env, ctx } = createTestEnv({ AI: ai });

		// 1) Wrong DTMF digit call
		const inc1 = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_FUNNEL_WRONG", From: "+13105550101" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		await ctx.flush();
		const digit1 = /please press (\d) on your keypad/.exec(await inc1.text())?.[1] ?? "2";
		const wrongDigit1 = digit1 === "2" ? "1" : "2";
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/dtmf`,
				{ CallSid: "CA_FUNNEL_WRONG", From: "+13105550101", Digits: wrongDigit1 },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/status`,
				{
					CallSid: "CA_FUNNEL_WRONG",
					From: "+13105550101",
					CallStatus: "completed",
					CallDuration: "18",
				},
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		await ctx.flush();

		// 2) Abandoned at L2 DTMF without pressing any digit (finalized via /voice/status)
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_FUNNEL_ABANDON", From: "+13105550102" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		await ctx.flush();
		const statusRes = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/status`,
				{
					CallSid: "CA_FUNNEL_ABANDON",
					From: "+13105550102",
					CallStatus: "completed",
					CallDuration: "12",
				},
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		expect(statusRes.status).toBe(204);
		await ctx.flush();

		// 3) Stopped by Clef AI at Layer 3 (loan scam)
		const inc3 = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_FUNNEL_SPAM", From: "+13105550103" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		await ctx.flush();
		const digit3 = /please press (\d) on your keypad/.exec(await inc3.text())?.[1] ?? "2";
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/dtmf`,
				{ CallSid: "CA_FUNNEL_SPAM", From: "+13105550103", Digits: digit3 },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/intent?attempt=1`,
				{
					CallSid: "CA_FUNNEL_SPAM",
					From: "+13105550103",
					SpeechResult: "Pre-approved business loan offer for fifty thousand dollars.",
				},
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/status`,
				{
					CallSid: "CA_FUNNEL_SPAM",
					From: "+13105550103",
					CallStatus: "completed",
					CallDuration: "35",
				},
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		await ctx.flush();

		// 4) Connected 30-min recruiter call (1800s SIP + 1815s inbound + 1 speech turn = 40.35 cents)
		const inc4 = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_FUNNEL_REC", From: "+12065550199" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		await ctx.flush();
		const digit4 = /please press (\d) on your keypad/.exec(await inc4.text())?.[1] ?? "2";
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/dtmf`,
				{ CallSid: "CA_FUNNEL_REC", From: "+12065550199", Digits: digit4 },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/intent?attempt=1`,
				{
					CallSid: "CA_FUNNEL_REC",
					From: "+12065550199",
					SpeechResult: "Hi Siobhan, calling from Stripe recruiting about your role.",
				},
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/dial-complete`,
				{
					CallSid: "CA_FUNNEL_REC",
					From: "+12065550199",
					DialCallStatus: "completed",
					DialCallDuration: "1800",
				},
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/status`,
				{
					CallSid: "CA_FUNNEL_REC",
					From: "+12065550199",
					CallStatus: "completed",
					CallDuration: "1815",
				},
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		await ctx.flush();

		const summaryRes = await worker.fetch(
			new Request(`${BASE_URL}/dashboard/api/summary?period=30d`, {
				headers: { "Cf-Access-Jwt-Assertion": validJwt },
			}),
			env,
			ctx,
		);
		expect(summaryRes.status).toBe(200);
		const summaryBody = (await summaryRes.json()) as { summary: DashboardSummary };
		expect(summaryBody.summary.totalCalls).toBe(4);
		expect(summaryBody.summary.spamStoppedCount).toBe(3);
		expect(summaryBody.summary.spamStoppedPct).toBe(75);
		expect(summaryBody.summary.stoppedAtL2Wrong).toBe(1);
		expect(summaryBody.summary.stoppedAtL2Abandoned).toBe(1);
		expect(summaryBody.summary.stoppedAtL3AiSpam).toBe(1);
		expect(summaryBody.summary.reachedUserCount).toBe(1);
		// 0.85 + 0.85 + 2.85 + 40.35 = 44.90 cents
		expect(summaryBody.summary.usageCostCents).toBe(44.9);
		expect(summaryBody.summary.fixedNumberCostCents).toBe(115);
		expect(summaryBody.summary.totalEstimatedCostCents).toBe(159.9);

		const l2CallsRes = await worker.fetch(
			new Request(`${BASE_URL}/dashboard/api/calls?phase=L2_DTMF`, {
				headers: { "Cf-Access-Jwt-Assertion": validJwt },
			}),
			env,
			ctx,
		);
		const l2Calls = (await l2CallsRes.json()) as { items: CallLogRow[]; total: number };
		expect(l2Calls.total).toBe(2);
		expect(l2Calls.items.map((row) => row.final_outcome).sort()).toEqual([
			"STOPPED_L2_DTMF_ABANDONED",
			"STOPPED_L2_DTMF_WRONG",
		]);
	});

	it("imports CSV allowlists, bypasses L1 for imported contacts, labels call logs, and exports CSV", async () => {
		const { env, ctx } = createTestEnv();

		const csvRes = await worker.fetch(
			new Request(`${BASE_URL}/dashboard/api/allowlist/csv`, {
				method: "POST",
				headers: {
					"Cf-Access-Jwt-Assertion": validJwt,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					mode: "merge",
					csv: "Name,Phone\nJordan Sister,+14155550101\nWife,(415) 555-0102\nInvalid,not-a-number\n",
				}),
			}),
			env,
			ctx,
		);
		expect(csvRes.status).toBe(200);
		expect(await csvRes.json()).toEqual({
			ok: true,
			imported: 2,
			updated: 0,
			skippedInvalid: 1,
			mode: "merge",
		});

		// CSV-imported number immediately bypasses screening at Layer 1
		const incomingRes = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_CSV_1", From: "+14155550101" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		await ctx.flush();
		const incomingXml = await incomingRes.text();
		expect(incomingXml).toContain("<Dial");
		expect(incomingXml).toContain(`<Sip>${env.SIP_ENDPOINT}</Sip>`);

		// Joined label appears in call logs
		const callsRes = await worker.fetch(
			new Request(`${BASE_URL}/dashboard/api/calls?search=4155550101`, {
				headers: { "Cf-Access-Jwt-Assertion": validJwt },
			}),
			env,
			ctx,
		);
		const callsData = (await callsRes.json()) as {
			items: Array<CallLogRow & { callerLabel: string | null }>;
		};
		expect(callsData.items[0]?.callerLabel).toBe("Jordan Sister");

		// Manual override to block, then delete
		const blockRes = await worker.fetch(
			new Request(`${BASE_URL}/dashboard/api/allowlist`, {
				method: "POST",
				headers: {
					"Cf-Access-Jwt-Assertion": validJwt,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					phone: "+14155550101",
					status: "blocked",
					reason: "Test block",
				}),
			}),
			env,
			ctx,
		);
		expect(blockRes.status).toBe(200);

		const blockedIncoming = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_CSV_2", From: "+14155550101" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
			ctx,
		);
		await ctx.flush();
		expect(await blockedIncoming.text()).toContain("<Hangup/>");

		const delRes = await worker.fetch(
			new Request(`${BASE_URL}/dashboard/api/allowlist`, {
				method: "DELETE",
				headers: {
					"Cf-Access-Jwt-Assertion": validJwt,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({ phone: "+14155550101" }),
			}),
			env,
			ctx,
		);
		expect(delRes.status).toBe(200);

		const rulesRes = await worker.fetch(
			new Request(`${BASE_URL}/dashboard/api/allowlist`, {
				headers: { "Cf-Access-Jwt-Assertion": validJwt },
			}),
			env,
			ctx,
		);
		const rulesData = (await rulesRes.json()) as { rules: CallerRuleRow[] };
		expect(rulesData.rules).toHaveLength(1);
		expect(rulesData.rules[0]?.phone_e164).toBe("+14155550102");

		const exportRes = await worker.fetch(
			new Request(`${BASE_URL}/dashboard/api/allowlist/export.csv`, {
				headers: { "Cf-Access-Jwt-Assertion": validJwt },
			}),
			env,
			ctx,
		);
		expect(exportRes.status).toBe(200);
		expect(exportRes.headers.get("Content-Type")).toContain("text/csv");
		expect(await exportRes.text()).toContain("+14155550102,Wife,allowed,csv");
	});
});
