import { describe, expect, it } from "vitest";
import worker from "../src/index.ts";
import {
	buildClefResponse,
	createSignedTwilioRequest,
	createTestEnv,
	MockAiRunner,
} from "./helpers/mockEnv.ts";

const BASE_URL = "https://firewall.example.com";

describe("You Shall Not Ring Worker end-to-end screening", () => {
	it("serves /health without leaking secrets and rejects unsigned Twilio webhooks", async () => {
		const { env } = createTestEnv();

		const healthRes = await worker.fetch(new Request(`${BASE_URL}/health`), env);
		expect(healthRes.status).toBe(200);
		expect(await healthRes.json()).toEqual({
			ok: true,
			service: "you-shall-not-ring",
		});

		const unsignedRes = await worker.fetch(
			new Request(`${BASE_URL}/voice/incoming`, {
				method: "POST",
				body: "CallSid=CA1&From=%2B14155550100",
			}),
			env,
		);
		expect(unsignedRes.status).toBe(403);
	});

	it("syncs contacts in 1 KV write, lets synced wife bypass screening, and cleans up removed contacts", async () => {
		const { env, kv, ai } = createTestEnv();

		const unauthRes = await worker.fetch(
			new Request(`${BASE_URL}/admin/contacts-sync`, {
				method: "POST",
				body: "+14155550100",
			}),
			env,
		);
		expect(unauthRes.status).toBe(401);

		const syncRes = await worker.fetch(
			new Request(`${BASE_URL}/admin/contacts-sync`, {
				method: "POST",
				headers: {
					Authorization: `Bearer ${env.ADMIN_TOKEN}`,
					"Content-Type": "text/plain",
				},
				body: "(415) 555-0100\n+1 415-555-0199\n+14155550100\n",
			}),
			env,
		);
		expect(syncRes.status).toBe(200);
		const syncData = (await syncRes.json()) as { ok: boolean; syncedCount: number };
		expect(syncData.ok).toBe(true);
		expect(syncData.syncedCount).toBe(2);
		expect(kv.putCount).toBe(1);

		// Synced contact bypasses Layer 2/3 -> immediate <Dial><Sip> with dial-complete action and NO whisper
		const incomingRes = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_WIFE_1", From: "+14155550100", To: "+14155559999" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const xml = await incomingRes.text();
		expect(xml).toContain(
			`<Dial answerOnBridge="true" timeout="25" action="${BASE_URL}/voice/dial-complete" method="POST" callerId="+14155550100">`,
		);
		expect(xml).toContain(`<Sip>${env.SIP_ENDPOINT}</Sip>`);
		expect(xml).not.toContain("/voice/whisper");
		expect(ai.calls).toHaveLength(0);

		// In CCF mode, missed synced contact goes to voicemail instead of re-ringing SIP
		const ccfRes = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_WIFE_CCF", From: "+14155550100" },
				env.TWILIO_AUTH_TOKEN,
			),
			{ ...env, ROUTING_MODE: "ccf" },
		);
		const ccfXml = await ccfRes.text();
		expect(ccfXml).toContain("<Record");
		expect(ccfXml).not.toContain("<Sip>");

		// Second sync removes +14155550199; next call hits Layer 2 DTMF
		await worker.fetch(
			new Request(`${BASE_URL}/admin/contacts-sync`, {
				method: "POST",
				headers: {
					Authorization: `Bearer ${env.ADMIN_TOKEN}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({ numbers: ["+14155550100"] }),
			}),
			env,
		);

		const removedContactRes = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_REMOVED", From: "+14155550199" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		expect(await removedContactRes.text()).toContain('input="dtmf"');
	});

	it("uses a clean speech prompt with 1 polite retry on silence and drops wrong DTMF", async () => {
		const { env, ai } = createTestEnv();

		const incomingRes = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_RETRY_1", From: "+13105550144" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const incomingXml = await incomingRes.text();
		expect(incomingXml).toContain("the call screening line for ");
		expect(incomingXml).not.toContain("Siobhan&apos;s");
		expect(incomingXml).toContain('<phoneme alphabet="ipa" ph="ʃəˈvɔːn">Siobhan</phoneme>');
		const expectedDigit =
			/please press (\d) on your keypad/.exec(incomingXml)?.[1] ?? "";
		expect(expectedDigit).toMatch(/^[2-9]$/);

		// Wrong digit drops immediately
		const wrongDigit = expectedDigit === "2" ? "3" : "2";
		const badDtmfRes = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/dtmf`,
				{ CallSid: "CA_RETRY_1", From: "+13105550144", Digits: wrongDigit },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		expect(await badDtmfRes.text()).toContain("<Hangup/>");

		// Fresh call passes Layer 2 -> gets clean speech prompt (no press-4 decoy!)
		const incoming2 = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_RETRY_2", From: "+13105550144" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const digit2 = /please press (\d) on your keypad/.exec(await incoming2.text())?.[1] ?? "";
		const goodDtmfRes = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/dtmf`,
				{ CallSid: "CA_RETRY_2", From: "+13105550144", Digits: digit2 },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const speechXml = await goodDtmfRes.text();
		expect(speechXml).toContain('input="speech"');
		expect(speechXml).not.toContain('input="speech dtmf"');
		expect(speechXml).not.toContain("press 4");
		expect(speechXml).toContain(`${BASE_URL}/voice/intent?attempt=1`);

		// Attempt 1 silence -> 1 polite retry (without calling Clef)
		const retryRes = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/intent?attempt=1`,
				{ CallSid: "CA_RETRY_2", From: "+13105550144", SpeechResult: "" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const retryXml = await retryRes.text();
		expect(retryXml).toContain("Sorry, I didn&apos;t catch that");
		expect(retryXml).toContain(`${BASE_URL}/voice/intent?attempt=2`);
		expect(ai.calls).toHaveLength(0);

		// Attempt 2 silence -> silent hangup
		const giveUpRes = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/intent?attempt=2`,
				{ CallSid: "CA_RETRY_2", From: "+13105550144", SpeechResult: "  " },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		expect(await giveUpRes.text()).toContain("<Hangup/>");
		expect(ai.calls).toHaveLength(0);
	});

	it("auto-connects ALLOW recruiters, blocks SPAM vendors, and routes UNCERTAIN via Press 1 / Press 2", async () => {
		const ai = new MockAiRunner(async (_model, inputs) => {
			const text = String(inputs.state ?? "");
			if (text.includes("Stripe")) {
				return buildClefResponse({
					routingChoice: "allow",
					routingConfidence: 0.96,
					categoryChoice: "recruiter",
				});
			}
			if (text.includes("LeadBoost")) {
				return buildClefResponse({
					routingChoice: "spam",
					routingConfidence: 0.93,
					categoryChoice: "vendor_pitch",
				});
			}
			return buildClefResponse({
				routingChoice: "uncertain",
				routingConfidence: 0.75,
				categoryChoice: "unclear",
			});
		});

		const { env } = createTestEnv({ AI: ai });

		// 1) ALLOW recruiter auto-allowlists + uses auto-connect whisper (no <Gather>)
		const recruiterPhone = "+12065550188";
		const recInc = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_REC_1", From: recruiterPhone },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const recDigit = /please press (\d) on your keypad/.exec(await recInc.text())?.[1] ?? "";
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/dtmf`,
				{ CallSid: "CA_REC_1", From: recruiterPhone, Digits: recDigit },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const recIntent = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/intent?attempt=1`,
				{
					CallSid: "CA_REC_1",
					From: recruiterPhone,
					SpeechResult: "Hi Siobhan, this is Maya from Stripe recruiting about your interview.",
				},
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const recDialXml = await recIntent.text();
		expect(recDialXml).toContain(`url="${BASE_URL}/voice/whisper?sid=CA_REC_1"`);

		const recWhisper = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/whisper?sid=CA_REC_1`,
				{ CallSid: "CA_CHILD_REC", ParentCallSid: "CA_REC_1" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const recWhisperXml = await recWhisper.text();
		expect(recWhisperXml).toContain("Recruiter: Hi Siobhan, this is Maya from Stripe");
		expect(recWhisperXml).toContain("Connecting now.");
		expect(recWhisperXml).not.toContain("<Gather");

		// Follow-up call from same recruiter skips straight past Layer 1
		const recFollowUp = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_REC_2", From: recruiterPhone },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		expect(await recFollowUp.text()).toContain("<Dial");

		// 2) SPAM vendor drops silently and stays un-allowlisted
		const vendorPhone = "+16505550177";
		const venInc = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_VEN_1", From: vendorPhone },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const venDigit = /please press (\d) on your keypad/.exec(await venInc.text())?.[1] ?? "";
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/dtmf`,
				{ CallSid: "CA_VEN_1", From: vendorPhone, Digits: venDigit },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const venIntent = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/intent?attempt=1`,
				{
					CallSid: "CA_VEN_1",
					From: vendorPhone,
					SpeechResult: "Hey I'm calling from LeadBoost SaaS to show you our outbound tool.",
				},
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		expect(await venIntent.text()).toContain("<Hangup/>");

		// 3) UNCERTAIN caller #1: Press 1 accepts and auto-allowlists
		const mikePhone = "+14255550111";
		const mikeInc = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_MIKE_1", From: mikePhone },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const mikeDigit = /please press (\d) on your keypad/.exec(await mikeInc.text())?.[1] ?? "";
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/dtmf`,
				{ CallSid: "CA_MIKE_1", From: mikePhone, Digits: mikeDigit },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/intent?attempt=1`,
				{
					CallSid: "CA_MIKE_1",
					From: mikePhone,
					SpeechResult: "Hey Siobhan, it's Mike, give me a call back.",
				},
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);

		const mikeWhisper = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/whisper?sid=CA_MIKE_1`,
				{ CallSid: "CA_CHILD_MIKE", ParentCallSid: "CA_MIKE_1" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const mikeWhisperXml = await mikeWhisper.text();
		expect(mikeWhisperXml).toContain("Uncertain call:");
		expect(mikeWhisperXml).toContain("Press 1 to accept, or 2 to block.");
		expect(mikeWhisperXml).toContain(`action="${BASE_URL}/voice/whisper-action?sid=CA_MIKE_1"`);

		// Press 1 bridges live & saves verified status for future calls
		const acceptRes = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/whisper-action?sid=CA_MIKE_1`,
				{ CallSid: "CA_CHILD_MIKE", Digits: "1" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const acceptXml = await acceptRes.text();
		expect(acceptXml).toContain("Connecting now.");
		expect(acceptXml).not.toContain("<Hangup/>");

		const mikeFollowUp = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_MIKE_2", From: mikePhone },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		expect(await mikeFollowUp.text()).toContain("<Dial");

		// 4) UNCERTAIN caller #2: Press 2 blocks permanently + dial-complete skips voicemail!
		const pestPhone = "+15095550122";
		const pestInc = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_PEST_1", From: pestPhone },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const pestDigit = /please press (\d) on your keypad/.exec(await pestInc.text())?.[1] ?? "";
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/dtmf`,
				{ CallSid: "CA_PEST_1", From: pestPhone, Digits: pestDigit },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/intent?attempt=1`,
				{
					CallSid: "CA_PEST_1",
					From: pestPhone,
					SpeechResult: "Hey it's Alex following up.",
				},
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);

		const rejectRes = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/whisper-action?sid=CA_PEST_1`,
				{ CallSid: "CA_CHILD_PEST", Digits: "2" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		expect(await rejectRes.text()).toContain("<Hangup/>");

		// Dial completion for the rejected caller must NOT offer voicemail
		const dialCompleteBlocked = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/dial-complete`,
				{ CallSid: "CA_PEST_1", From: pestPhone, DialCallStatus: "no-answer" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		expect(await dialCompleteBlocked.text()).toContain("<Hangup/>");

		// Future calls from pestPhone drop immediately at Layer 1
		const pestRetry = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_PEST_2", From: pestPhone },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		expect(await pestRetry.text()).toContain("<Hangup/>");

		// Genuine missed call from non-blocked caller reaches voicemail with IPA pronunciation
		const dialCompleteMissed = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/dial-complete`,
				{ CallSid: "CA_REC_1", From: recruiterPhone, DialCallStatus: "no-answer" },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		const voicemailXml = await dialCompleteMissed.text();
		expect(voicemailXml).toContain("<Record");
		expect(voicemailXml).toContain('<phoneme alphabet="ipa" ph="ʃəˈvɔːn">Siobhan</phoneme>');
	});

	it("lets explicit admin blocks override synced contacts and allows clearing blocks", async () => {
		const { env } = createTestEnv();
		const target = "+14155550155";

		await worker.fetch(
			new Request(`${BASE_URL}/admin/contacts-sync`, {
				method: "POST",
				headers: {
					Authorization: `Bearer ${env.ADMIN_TOKEN}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({ numbers: [target] }),
			}),
			env,
		);

		const blockRes = await worker.fetch(
			new Request(`${BASE_URL}/admin/allowlist`, {
				method: "POST",
				headers: {
					Authorization: `Bearer ${env.ADMIN_TOKEN}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({ phone: target, status: "blocked", reason: "Persistent vendor" }),
			}),
			env,
		);
		expect(blockRes.status).toBe(200);

		const blockedCall = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_BLK_1", From: target },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		expect(await blockedCall.text()).toContain("<Hangup/>");

		const unblockRes = await worker.fetch(
			new Request(`${BASE_URL}/admin/allowlist`, {
				method: "DELETE",
				headers: {
					Authorization: `Bearer ${env.ADMIN_TOKEN}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({ phone: target }),
			}),
			env,
		);
		expect(unblockRes.status).toBe(200);

		const restoredCall = await worker.fetch(
			await createSignedTwilioRequest(
				`${BASE_URL}/voice/incoming`,
				{ CallSid: "CA_BLK_2", From: target },
				env.TWILIO_AUTH_TOKEN,
			),
			env,
		);
		expect(await restoredCall.text()).toContain("<Dial");
	});
});
