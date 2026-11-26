import { withSecurityHeaders } from "../security/http.ts";

const DEFAULT_VOICE = "Polly.Joanna-Neural";

/**
 * Escapes XML special characters before embedding dynamic values into TwiML.
 *
 * Why strict XML escaping: Spoken caller summaries, URLs with query parameters,
 * and owner names could otherwise break XML parsing or inject unintended TwiML verbs.
 *
 * @param input - Untrusted or dynamic string value.
 * @returns XML-safe text.
 */
export function escapeXml(input: string): string {
	return input
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&apos;");
}

/**
 * Wraps inner TwiML elements in a standard XML `<Response>` HTTP response.
 *
 * @param innerXml - Inner TwiML body nodes.
 * @returns HTTP 200 XML `Response` with `Cache-Control: no-store` and security headers.
 */
export function twimlResponse(innerXml: string): Response {
	const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<Response>${innerXml}</Response>`;
	return new Response(xml, {
		status: 200,
		headers: withSecurityHeaders({
			"Content-Type": "text/xml; charset=utf-8",
			"Cache-Control": "no-store",
		}),
	});
}

/**
 * Returns an immediate silent hangup so rejected robocalls never disturb the iPhone.
 */
export function buildHangupTwiml(): Response {
	return twimlResponse("<Hangup/>");
}

/**
 * Formats the owner's display name with an optional SSML `<phoneme>` tag for Amazon Polly.
 *
 * Why SSML phoneme markup: Possessive phrasing or unfamiliar name spellings can shift
 * Polly Neural syllable stress across prompts; wrapping in `<phoneme alphabet="ipa">`
 * enforces consistent pronunciation everywhere.
 *
 * @param ownerName - Display name spoken in TwiML prompts.
 * @param ownerNameIpa - Optional Amazon Polly en-US IPA string (e.g. `"ʃəˈvɔːn"`).
 * @returns XML-safe text or `<phoneme>` element ready for insertion inside `<Say>`.
 */
export function formatSpokenOwnerName(ownerName: string, ownerNameIpa?: string): string {
	const safeOwner = escapeXml(ownerName);
	const trimmedIpa = ownerNameIpa?.trim();
	if (!trimmedIpa) {
		return safeOwner;
	}
	return `<phoneme alphabet="ipa" ph="${escapeXml(trimmedIpa)}">${safeOwner}</phoneme>`;
}

/**
 * Builds Layer 2 randomized keypad verification TwiML.
 *
 * Why randomized digits `2–9`: Automated robodialers routinely blast `1` or `0`
 * to navigate IVRs, whereas a human caller easily enters the spoken digit.
 *
 * @param expectedDigit - Single digit between `"2"` and `"9"`.
 * @param ownerName - Display name spoken in the screening greeting.
 * @param actionUrl - Absolute webhook URL for `/voice/dtmf`.
 * @param ownerNameIpa - Optional IPA pronunciation override for Amazon Polly.
 */
export function buildDtmfChallengeTwiml(
	expectedDigit: string,
	ownerName: string,
	actionUrl: string,
	ownerNameIpa?: string,
): Response {
	const spokenOwner = formatSpokenOwnerName(ownerName, ownerNameIpa);
	const safeDigit = escapeXml(expectedDigit);
	const safeAction = escapeXml(actionUrl);

	return twimlResponse(
		`<Gather input="dtmf" numDigits="1" timeout="7" action="${safeAction}" method="POST">` +
			`<Say voice="${DEFAULT_VOICE}">Hello, you have reached the call screening line for ${spokenOwner}. To continue, please press ${safeDigit} on your keypad.</Say>` +
			`</Gather>` +
			`<Hangup/>`,
	);
}

/**
 * Options for constructing the Layer 3 speech recognition prompt.
 */
export interface SpeechChallengeOptions {
	actionUrl: string;
	isRetry?: boolean;
}

/**
 * Builds Layer 3 clean speech-only screening TwiML with optional single polite retry.
 *
 * Why `<Redirect>` on the first attempt: Twilio falls past `</Gather>` without firing
 * `action` when a caller stays silent through the timeout; redirecting to `actionUrl`
 * ensures a legitimate caller who paused gets one polite retry before hanging up.
 */
export function buildSpeechChallengeTwiml(options: SpeechChallengeOptions): Response {
	const safeAction = escapeXml(options.actionUrl);
	const speechHints = escapeXml(
		"recruiter,interview,job,buying,marketplace,delivery,doctor,appointment,customer service,support,mechanic,contractor,billing,loan,IRS,tax,vendor,software,demo",
	);

	const promptText = options.isRetry
		? "Sorry, I didn&apos;t catch that. Please say your name and why you are calling."
		: "Thank you. Please state your name and a brief reason for calling.";

	const timeoutFallback = options.isRetry
		? "<Hangup/>"
		: `<Redirect method="POST">${safeAction}</Redirect>`;

	return twimlResponse(
		`<Gather input="speech" speechTimeout="auto" timeout="6" hints="${speechHints}" action="${safeAction}" method="POST">` +
			`<Say voice="${DEFAULT_VOICE}">${promptText}</Say>` +
			`</Gather>` +
			timeoutFallback,
	);
}

/**
 * Options for bridging an approved or uncertain call to the user's CallKit SIP endpoint.
 */
export interface DialSipOptions {
	sipEndpoint: string;
	callerId: string | null;
	dialActionUrl: string;
	whisperUrl?: string;
	timeoutSeconds?: number;
}

/**
 * Bridges a verified, allowlisted, or uncertain call to the user's SIP client over IP data.
 *
 * Why `answerOnBridge="true"`, `<Sip url="...">`, and `<Dial action="...">`:
 * - Placing `url` on `<Sip>` (never on `<Dial>`, which Twilio rejects) plays the whisper
 *   exclusively to you when you answer, while `answerOnBridge="true"` keeps the caller
 *   hearing normal ringback until bridging occurs.
 * - Routing Dial completion to `dialActionUrl` ensures missed calls get voicemail while
 *   callers rejected via Press `2` during the whisper are terminated silently.
 */
export function buildDialSipTwiml(options: DialSipOptions): Response {
	const timeout = options.timeoutSeconds ?? 25;
	const safeEndpoint = escapeXml(options.sipEndpoint);
	const safeDialAction = escapeXml(options.dialActionUrl);

	const callerIdAttr = options.callerId ? ` callerId="${escapeXml(options.callerId)}"` : "";
	const whisperAttr = options.whisperUrl ? ` url="${escapeXml(options.whisperUrl)}"` : "";

	return twimlResponse(
		`<Dial answerOnBridge="true" timeout="${timeout}" action="${safeDialAction}" method="POST"${callerIdAttr}>` +
			`<Sip${whisperAttr}>${safeEndpoint}</Sip>` +
			`</Dial>`,
	);
}

/**
 * Plays a concise auto-connect whisper summary exclusively to the callee before bridging audio.
 *
 * @param summary - Sanitized caller summary saved in KV.
 */
export function buildAutoWhisperTwiml(summary: string): Response {
	const safeSummary = escapeXml(summary);
	return twimlResponse(
		`<Say voice="${DEFAULT_VOICE}">${safeSummary}. Connecting now.</Say>`,
	);
}

/**
 * Plays an interactive Press-1 / Press-2 whisper for uncertain callers before bridging.
 *
 * @param summary - Sanitized caller summary saved in KV.
 * @param actionUrl - Absolute webhook URL for `/voice/whisper-action`.
 */
export function buildConfirmWhisperTwiml(summary: string, actionUrl: string): Response {
	const safeSummary = escapeXml(summary);
	const safeAction = escapeXml(actionUrl);

	return twimlResponse(
		`<Gather input="dtmf" numDigits="1" timeout="10" action="${safeAction}" method="POST">` +
			`<Say voice="${DEFAULT_VOICE}">Uncertain call: &quot;${safeSummary}&quot;. End of caller note. Press 1 to accept, or 2 to block.</Say>` +
			`</Gather>` +
			`<Hangup/>`,
	);
}

/**
 * Completes the whisper leg without hanging up so Twilio bridges the live call immediately.
 */
export function buildAcceptBridgeTwiml(): Response {
	return twimlResponse(`<Say voice="${DEFAULT_VOICE}">Connecting now.</Say>`);
}

/**
 * Sends a missed allowlisted or unblocked caller directly to Twilio voicemail.
 *
 * Why explicit `action` and trailing `<Hangup/>`: Without `action`, Twilio re-POSTs to the
 * current webhook URL after `<Record>` finishes or sees `#`, causing an infinite recording loop.
 *
 * @param ownerName - Display name spoken in the voicemail greeting.
 * @param ownerNameIpa - Optional IPA pronunciation override for Amazon Polly.
 * @param recordActionUrl - Webhook URL invoked after recording completes.
 */
export function buildVoicemailTwiml(
	ownerName: string,
	ownerNameIpa?: string,
	recordActionUrl = "/voice/voicemail-complete",
): Response {
	const spokenOwner = formatSpokenOwnerName(ownerName, ownerNameIpa);
	const safeAction = escapeXml(recordActionUrl);
	return twimlResponse(
		`<Say voice="${DEFAULT_VOICE}">Hi, you have reached ${spokenOwner}. Please leave a message after the tone.</Say>` +
			`<Record maxLength="60" playBeep="true" action="${safeAction}" method="POST"/>` +
			`<Hangup/>`,
	);
}
