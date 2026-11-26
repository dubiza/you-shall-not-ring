import { describe, expect, it } from "vitest";
import {
	constantTimeEqual,
	hashPhoneNumber,
	normalizePhoneNumber,
	verifyBearerToken,
} from "../src/security/crypto.ts";
import { computeTwilioSignature, verifyTwilioRequest } from "../src/security/twilioSignature.ts";

describe("phone normalization and salted hashing", () => {
	it("normalizes varied US and international formats to E.164", () => {
		expect(normalizePhoneNumber("(415) 555-0199")).toBe("+14155550199");
		expect(normalizePhoneNumber("1-415-555-0199")).toBe("+14155550199");
		expect(normalizePhoneNumber(" +1 415.555.0199 ")).toBe("+14155550199");
		expect(normalizePhoneNumber("00442079460958")).toBe("+442079460958");
		expect(normalizePhoneNumber("+442079460958")).toBe("+442079460958");
	});

	it("rejects anonymous, restricted, and malformed caller identifiers", () => {
		expect(normalizePhoneNumber("")).toBeNull();
		expect(normalizePhoneNumber("anonymous")).toBeNull();
		expect(normalizePhoneNumber("Restricted")).toBeNull();
		expect(normalizePhoneNumber("unknown")).toBeNull();
		expect(normalizePhoneNumber("12345")).toBeNull();
		expect(normalizePhoneNumber("sip:bot@example.com")).toBeNull();
	});

	it("produces deterministic 128-bit salted HMAC digests and rejects empty salt", async () => {
		const h1 = await hashPhoneNumber("+14155550199", "salt-a");
		const h2 = await hashPhoneNumber("+14155550199", "salt-a");
		const h3 = await hashPhoneNumber("+14155550199", "salt-b");

		expect(h1).toHaveLength(32);
		expect(h1).toBe(h2);
		expect(h1).not.toBe(h3);
		await expect(hashPhoneNumber("+14155550199", "")).rejects.toThrow(/CONTACT_HASH_SALT/);
	});

	it("validates constant-time equality and Bearer tokens", async () => {
		expect(await constantTimeEqual("abc123", "abc123")).toBe(true);
		expect(await constantTimeEqual("abc123", "abc124")).toBe(false);
		expect(await constantTimeEqual("short", "much-longer-secret")).toBe(false);

		expect(await verifyBearerToken("Bearer super-secret", "super-secret")).toBe(true);
		expect(await verifyBearerToken("bearer super-secret", "super-secret")).toBe(true);
		expect(await verifyBearerToken("Basic super-secret", "super-secret")).toBe(false);
		expect(await verifyBearerToken("Bearer wrong", "super-secret")).toBe(false);
		expect(await verifyBearerToken(null, "super-secret")).toBe(false);
		expect(await verifyBearerToken("Bearer secret", "")).toBe(false);
	});
});

describe("Twilio X-Twilio-Signature verification", () => {
	const authToken = "twilio-secret-token";
	const url = "https://firewall.example.com/voice/incoming";

	it("accepts authentic signed requests including query strings and forwarded headers", async () => {
		const params = {
			CallSid: "CA123456",
			From: "+14155550100",
			To: "+14155559999",
		};
		const queryUrl = "https://firewall.example.com/voice/whisper?sid=CA123456";
		const sig = await computeTwilioSignature(queryUrl, params, authToken);

		const req = new Request(queryUrl, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				"X-Twilio-Signature": sig,
			},
			body: new URLSearchParams(params).toString(),
		});
		expect(await verifyTwilioRequest(req, params, authToken)).toBe(true);

		// Simulate Worker behind a reverse proxy rewriting request.url host/proto
		const internalReq = new Request("http://internal.local/voice/whisper?sid=CA123456", {
			method: "POST",
			headers: {
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host": "firewall.example.com",
				"X-Twilio-Signature": sig,
			},
		});
		expect(await verifyTwilioRequest(internalReq, params, authToken)).toBe(true);
	});

	it("rejects missing, tampered, wrong-token, and malformed signatures", async () => {
		const params = { CallSid: "CA999", From: "+14155550100" };
		const sig = await computeTwilioSignature(url, params, authToken);

		const tampered = new Request(url, {
			method: "POST",
			headers: { "X-Twilio-Signature": sig },
		});
		expect(
			await verifyTwilioRequest(tampered, { CallSid: "CA999", From: "+14155550101" }, authToken),
		).toBe(false);

		const wrongToken = new Request(url, {
			method: "POST",
			headers: { "X-Twilio-Signature": sig },
		});
		expect(await verifyTwilioRequest(wrongToken, params, "different-token")).toBe(false);

		const malformed = new Request(url, {
			method: "POST",
			headers: { "X-Twilio-Signature": "!!!not-base64!!!" },
		});
		expect(await verifyTwilioRequest(malformed, params, authToken)).toBe(false);

		const unsigned = new Request(url, { method: "POST" });
		expect(await verifyTwilioRequest(unsigned, params, authToken)).toBe(false);
	});
});
