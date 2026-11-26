import { classifyCallerIntent } from "../ai/intentClassifier.ts";
import { normalizePhoneNumber } from "../security/crypto.ts";
import { verifyTwilioRequest } from "../security/twilioSignature.ts";
import {
	finalizeCallStatus,
	pruneExpiredCallLogs,
	updateCallProgress,
	upsertCallStart,
} from "../storage/callLogs.ts";
import {
	consumeDtmfChallenge,
	getWhisperContext,
	lookupCallerStatus,
	saveDtmfChallenge,
	saveWhisperContext,
	setCallerRecord,
} from "../storage/callerList.ts";
import { lookupCallerRule, upsertCallerRule } from "../storage/callerRules.ts";
import {
	buildAcceptBridgeTwiml,
	buildAutoWhisperTwiml,
	buildConfirmWhisperTwiml,
	buildDialSipTwiml,
	buildDtmfChallengeTwiml,
	buildHangupTwiml,
	buildSpeechChallengeTwiml,
	buildVoicemailTwiml,
} from "../twiml/builder.ts";
import type {
	CallerRuleRow,
	CallerStatus,
	ExecutionWaitUntil,
	RoutingMode,
	CallFirewallEnv,
} from "../types.ts";

// Exclude "1" and "0" because automated dialers routinely spam them to clear phone menus.
const CHALLENGE_DIGITS = ["2", "3", "4", "5", "6", "7", "8", "9"] as const;
const THIRTY_DAYS_SECONDS = 30 * 86400;
const TERMINAL_CALL_STATUSES = new Set([
	"completed",
	"busy",
	"no-answer",
	"canceled",
	"failed",
]);

/**
 * Schedules a non-blocking D1 telemetry task via `ctx.waitUntil`, logging any errors.
 *
 * Why isolate telemetry failures: D1 outages or transient SQL errors must never break
 * live Twilio call-screening webhooks.
 */
function enqueueTelemetry(
	ctx: ExecutionWaitUntil | undefined,
	task: () => Promise<void>,
): void {
	const promise = Promise.resolve()
		.then(task)
		.catch((error: unknown) => {
			console.error("Call telemetry write failed", error);
		});
	ctx?.waitUntil(promise);
}

/**
 * Persists a caller allow/block rule in D1 while catching and logging errors so live calls never drop.
 */
async function persistCallerRuleSafely(
	env: CallFirewallEnv,
	input: Parameters<typeof upsertCallerRule>[1],
): Promise<void> {
	try {
		await upsertCallerRule(env.CALL_LOGS_DB, input);
	} catch (error) {
		console.error("Failed to persist D1 caller rule", error);
	}
}

/**
 * Looks up a Layer 1 D1 caller rule while falling back gracefully to KV if D1 errors.
 */
async function lookupCallerRuleSafely(
	env: CallFirewallEnv,
	normalizedE164: string,
): Promise<CallerRuleRow | null> {
	try {
		return await lookupCallerRule(env.CALL_LOGS_DB, normalizedE164);
	} catch (error) {
		console.error("Failed to look up D1 caller rule; falling back to KV", error);
		return null;
	}
}

/**
 * Generates an unbiased random digit from `"2"` through `"9"` using CSPRNG bytes.
 */
function pickRandomChallengeDigit(): string {
	const buffer = new Uint8Array(1);
	// Rejection sampling avoids modulo bias across the 8-element digit pool.
	const limit = 256 - (256 % CHALLENGE_DIGITS.length);
	while (true) {
		crypto.getRandomValues(buffer);
		const byte = buffer[0] ?? 0;
		if (byte < limit) {
			return CHALLENGE_DIGITS[byte % CHALLENGE_DIGITS.length] ?? "7";
		}
	}
}

/**
 * Parses a Twilio `application/x-www-form-urlencoded` body into a flat string map.
 */
async function parseTwilioForm(request: Request): Promise<Record<string, string>> {
	const rawBody = await request.text();
	const params = new URLSearchParams(rawBody);
	const record: Record<string, string> = {};
	for (const [key, value] of params.entries()) {
		record[key] = value;
	}
	return record;
}

/**
 * Parses configured `ROUTING_MODE` safely with `"all"` as the default.
 */
function resolveRoutingMode(raw?: string): RoutingMode {
	return raw?.trim().toLowerCase() === "ccf" ? "ccf" : "all";
}

/**
 * Resolves owner display name used in spoken TwiML prompts.
 */
function resolveOwnerName(raw?: string): string {
	const trimmed = raw?.trim();
	return trimmed && trimmed.length > 0 ? trimmed : "the owner";
}

/**
 * Routes an allowlisted Layer 1 caller to SIP or voicemail and enqueues start telemetry.
 */
function respondAllowlistedCaller(
	env: CallFirewallEnv,
	origin: string,
	callSid: string,
	normalizedFrom: string,
	ownerName: string,
	routingMode: RoutingMode,
	callerTrust: CallerStatus,
	allowReason: string,
	ctx?: ExecutionWaitUntil,
): Response {
	// In Contacts-Direct (CCF) mode, reaching Twilio means the native iPhone dialer already
	// rang and was missed/declined, so send to voicemail rather than re-ringing over SIP.
	if (routingMode === "ccf") {
		if (callSid) {
			enqueueTelemetry(ctx, () =>
				upsertCallStart(env.CALL_LOGS_DB, {
					callSid,
					fromNumber: normalizedFrom,
					callerTrust,
					furthestPhase: "VOICEMAIL",
					finalOutcome: "MISSED_VOICEMAIL",
					outcomeReason: "Missed contact in CCF mode",
				}),
			);
		}
		return buildVoicemailTwiml(ownerName, env.OWNER_NAME_IPA);
	}

	if (!env.SIP_ENDPOINT) {
		console.error("SIP_ENDPOINT secret is missing; falling back to voicemail");
		if (callSid) {
			enqueueTelemetry(ctx, () =>
				upsertCallStart(env.CALL_LOGS_DB, {
					callSid,
					fromNumber: normalizedFrom,
					callerTrust,
					furthestPhase: "VOICEMAIL",
					finalOutcome: "MISSED_VOICEMAIL",
					outcomeReason: "SIP endpoint not configured; sent to voicemail",
				}),
			);
		}
		return buildVoicemailTwiml(ownerName, env.OWNER_NAME_IPA);
	}

	if (callSid) {
		enqueueTelemetry(ctx, () =>
			upsertCallStart(env.CALL_LOGS_DB, {
				callSid,
				fromNumber: normalizedFrom,
				callerTrust,
				furthestPhase: "BRIDGED",
				finalOutcome: "CONNECTED_ALLOWLIST",
				outcomeReason: allowReason,
			}),
		);
	}

	return buildDialSipTwiml({
		sipEndpoint: env.SIP_ENDPOINT,
		callerId: normalizedFrom,
		dialActionUrl: `${origin}/voice/dial-complete`,
	});
}

/**
 * Handles Layer 1 allowlist lookup and initiates Layer 2 DTMF screening for unknown callers.
 */
async function handleIncomingCall(
	env: CallFirewallEnv,
	origin: string,
	params: Record<string, string>,
	ctx?: ExecutionWaitUntil,
): Promise<Response> {
	const ownerName = resolveOwnerName(env.OWNER_NAME);
	const routingMode = resolveRoutingMode(env.ROUTING_MODE);
	const callSid = params.CallSid?.trim() ?? "";
	const normalizedFrom = normalizePhoneNumber(params.From ?? "");

	if (normalizedFrom) {
		// Check D1 caller_rules first so dashboard CSV/manual rules take precedence before KV hashes.
		const rule = await lookupCallerRuleSafely(env, normalizedFrom);

		if (rule?.status === "blocked") {
			if (callSid) {
				enqueueTelemetry(ctx, () =>
					upsertCallStart(env.CALL_LOGS_DB, {
						callSid,
						fromNumber: normalizedFrom,
						callerTrust: "blocked",
						furthestPhase: "L1_ALLOWLIST",
						finalOutcome: "BLOCKED_L1",
						outcomeReason: rule.reason || "Blocked by caller rule",
					}),
				);
			}
			return buildHangupTwiml();
		}

		if (rule?.status === "allowed") {
			const callerTrust: CallerStatus =
				rule.source === "csv" || rule.source === "manual" ? "contact" : "verified";
			const allowReason = rule.label
				? `Allowlisted (${rule.label})`
				: `Allowlisted (${rule.source})`;
			return respondAllowlistedCaller(
				env,
				origin,
				callSid,
				normalizedFrom,
				ownerName,
				routingMode,
				callerTrust,
				allowReason,
				ctx,
			);
		}

		const status = await lookupCallerStatus(
			env.ALLOWLIST_KV,
			normalizedFrom,
			env.CONTACT_HASH_SALT,
		);

		if (status === "blocked") {
			if (callSid) {
				enqueueTelemetry(ctx, () =>
					upsertCallStart(env.CALL_LOGS_DB, {
						callSid,
						fromNumber: normalizedFrom,
						callerTrust: "blocked",
						furthestPhase: "L1_ALLOWLIST",
						finalOutcome: "BLOCKED_L1",
						outcomeReason: "Blocked in KV allowlist",
					}),
				);
			}
			return buildHangupTwiml();
		}

		if (status === "contact" || status === "verified") {
			const allowReason =
				status === "contact" ? "Synced iPhone contact" : "Allowlisted (KV verified)";
			return respondAllowlistedCaller(
				env,
				origin,
				callSid,
				normalizedFrom,
				ownerName,
				routingMode,
				status,
				allowReason,
				ctx,
			);
		}
	}

	if (!callSid) {
		console.warn("Incoming call missing CallSid; dropping safely");
		return buildHangupTwiml();
	}

	const expectedDigit = pickRandomChallengeDigit();
	await saveDtmfChallenge(env.ALLOWLIST_KV, callSid, {
		expectedDigit,
		fromE164: normalizedFrom,
		createdAt: new Date().toISOString(),
	});

	const fromNumber = normalizedFrom ?? (params.From?.trim() || "anonymous");
	enqueueTelemetry(ctx, () =>
		upsertCallStart(env.CALL_LOGS_DB, {
			callSid,
			fromNumber,
			callerTrust: "unknown",
			furthestPhase: "L2_DTMF",
			finalOutcome: "IN_PROGRESS",
			expectedDigit,
			outcomeReason: "Awaiting keypad verification",
		}),
	);

	return buildDtmfChallengeTwiml(
		expectedDigit,
		ownerName,
		`${origin}/voice/dtmf`,
		env.OWNER_NAME_IPA,
	);
}

/**
 * Validates the Layer 2 DTMF digit and promotes passing callers to Layer 3 speech screening.
 */
async function handleDtmfStep(
	env: CallFirewallEnv,
	origin: string,
	params: Record<string, string>,
	ctx?: ExecutionWaitUntil,
): Promise<Response> {
	const callSid = params.CallSid?.trim() ?? "";
	const digits = params.Digits?.trim() ?? "";

	if (!callSid) {
		return buildHangupTwiml();
	}

	const challenge = await consumeDtmfChallenge(env.ALLOWLIST_KV, callSid);
	if (!challenge || digits !== challenge.expectedDigit) {
		const pressedDigit = digits || "none";
		enqueueTelemetry(ctx, () =>
			updateCallProgress(env.CALL_LOGS_DB, callSid, {
				furthestPhase: "L2_DTMF",
				finalOutcome: "STOPPED_L2_DTMF_WRONG",
				pressedDigit,
				outcomeReason: `Pressed "${pressedDigit}" instead of "${challenge?.expectedDigit ?? "?"}"`,
			}),
		);
		return buildHangupTwiml();
	}

	enqueueTelemetry(ctx, () =>
		updateCallProgress(env.CALL_LOGS_DB, callSid, {
			furthestPhase: "L3_SPEECH",
			pressedDigit: digits,
		}),
	);

	return buildSpeechChallengeTwiml({
		actionUrl: `${origin}/voice/intent?attempt=1`,
		isRetry: false,
	});
}

/**
 * Runs Layer 3 single-retry guard and Cloudflare Clef 3-way routing (`ALLOW`, `SPAM`, `UNCERTAIN`).
 */
async function handleIntentStep(
	env: CallFirewallEnv,
	origin: string,
	url: URL,
	params: Record<string, string>,
	ctx?: ExecutionWaitUntil,
): Promise<Response> {
	const callSid = params.CallSid?.trim() ?? "";
	const speechResult = params.SpeechResult?.trim() ?? "";
	const ownerName = resolveOwnerName(env.OWNER_NAME);
	const parsedAttempt = Number(url.searchParams.get("attempt") ?? "1");
	const attempt = Number.isFinite(parsedAttempt) && parsedAttempt >= 1 ? parsedAttempt : 1;

	if (speechResult.length < 3) {
		if (attempt < 2) {
			if (callSid) {
				enqueueTelemetry(ctx, () =>
					updateCallProgress(env.CALL_LOGS_DB, callSid, {
						furthestPhase: "L3_SPEECH",
						speechAttemptsIncrement: 1,
						outcomeReason: "First speech prompt silent; retrying",
					}),
				);
			}
			return buildSpeechChallengeTwiml({
				actionUrl: `${origin}/voice/intent?attempt=2`,
				isRetry: true,
			});
		}

		if (callSid) {
			enqueueTelemetry(ctx, () =>
				updateCallProgress(env.CALL_LOGS_DB, callSid, {
					furthestPhase: "L3_SPEECH",
					finalOutcome: "STOPPED_L3_SILENCE",
					speechAttemptsIncrement: 1,
					outcomeReason: "No speech detected after retry",
				}),
			);
		}
		return buildHangupTwiml();
	}

	const classification = await classifyCallerIntent(env, speechResult);
	if (classification.decision === "SPAM") {
		if (callSid) {
			enqueueTelemetry(ctx, () =>
				updateCallProgress(env.CALL_LOGS_DB, callSid, {
					furthestPhase: "L3_CLEF",
					finalOutcome: "STOPPED_L3_AI_SPAM",
					speechAttemptsIncrement: 1,
					transcript: speechResult,
					aiDecision: "SPAM",
					aiCategory: classification.category,
					aiConfidence: classification.confidence,
					promptInjectionScore: classification.promptInjectionScore,
					outcomeReason: classification.reason,
				}),
			);
		}
		console.info(`Dropped screened call category=${classification.category}`);
		return buildHangupTwiml();
	}

	const normalizedFrom = normalizePhoneNumber(params.From ?? "");
	const mode = classification.decision === "ALLOW" ? "auto" : "confirm";

	if (mode === "auto" && normalizedFrom) {
		await Promise.all([
			setCallerRecord(
				env.ALLOWLIST_KV,
				normalizedFrom,
				env.CONTACT_HASH_SALT,
				"verified",
				classification.category,
			),
			persistCallerRuleSafely(env, {
				phoneE164: normalizedFrom,
				status: "allowed",
				source: "auto_clef",
				reason: classification.category,
				ttlSeconds: THIRTY_DAYS_SECONDS,
			}),
		]);
	}

	if (!env.SIP_ENDPOINT) {
		console.error("SIP_ENDPOINT secret is missing; falling back to voicemail");
		if (callSid) {
			enqueueTelemetry(ctx, () =>
				updateCallProgress(env.CALL_LOGS_DB, callSid, {
					furthestPhase: "VOICEMAIL",
					finalOutcome: "MISSED_VOICEMAIL",
					speechAttemptsIncrement: 1,
					transcript: speechResult,
					aiDecision: classification.decision,
					aiCategory: classification.category,
					aiConfidence: classification.confidence,
					promptInjectionScore: classification.promptInjectionScore,
					outcomeReason: "SIP endpoint not configured; sent to voicemail",
				}),
			);
		}
		return buildVoicemailTwiml(ownerName, env.OWNER_NAME_IPA);
	}

	let whisperUrl: string | undefined;
	if (callSid) {
		await saveWhisperContext(env.ALLOWLIST_KV, callSid, {
			summary: classification.whisperSummary,
			mode,
			fromE164: normalizedFrom,
			category: classification.category,
		});
		whisperUrl = `${origin}/voice/whisper?sid=${encodeURIComponent(callSid)}`;

		if (classification.decision === "ALLOW") {
			enqueueTelemetry(ctx, () =>
				updateCallProgress(env.CALL_LOGS_DB, callSid, {
					furthestPhase: "BRIDGED",
					finalOutcome: "CONNECTED_AI_ALLOW",
					speechAttemptsIncrement: 1,
					transcript: speechResult,
					aiDecision: "ALLOW",
					aiCategory: classification.category,
					aiConfidence: classification.confidence,
					promptInjectionScore: classification.promptInjectionScore,
					outcomeReason: classification.reason,
				}),
			);
		} else {
			enqueueTelemetry(ctx, () =>
				updateCallProgress(env.CALL_LOGS_DB, callSid, {
					furthestPhase: "WHISPER",
					finalOutcome: "IN_PROGRESS",
					speechAttemptsIncrement: 1,
					transcript: speechResult,
					aiDecision: "UNCERTAIN",
					aiCategory: classification.category,
					aiConfidence: classification.confidence,
					promptInjectionScore: classification.promptInjectionScore,
					outcomeReason: "Awaiting live Press-1 confirmation",
				}),
			);
		}
	}

	return buildDialSipTwiml({
		sipEndpoint: env.SIP_ENDPOINT,
		callerId: normalizedFrom,
		dialActionUrl: `${origin}/voice/dial-complete`,
		whisperUrl,
	});
}

/**
 * Returns either an auto-connect whisper (`ALLOW`) or a Press-1/Press-2 interactive whisper (`UNCERTAIN`).
 */
async function handleWhisperStep(
	env: CallFirewallEnv,
	origin: string,
	url: URL,
	params: Record<string, string>,
): Promise<Response> {
	const sid =
		url.searchParams.get("sid")?.trim() ||
		params.ParentCallSid?.trim() ||
		params.CallSid?.trim() ||
		"";

	const context = await getWhisperContext(env.ALLOWLIST_KV, sid);
	if (context?.mode === "confirm") {
		return buildConfirmWhisperTwiml(
			context.summary,
			`${origin}/voice/whisper-action?sid=${encodeURIComponent(sid)}`,
		);
	}

	return buildAutoWhisperTwiml(context?.summary ?? "Verified caller");
}

/**
 * Handles the callee's Press-1 (accept + 30-day allowlist) or Press-2 (permanent block) decision.
 */
async function handleWhisperActionStep(
	env: CallFirewallEnv,
	url: URL,
	params: Record<string, string>,
	ctx?: ExecutionWaitUntil,
): Promise<Response> {
	const sid =
		url.searchParams.get("sid")?.trim() ||
		params.ParentCallSid?.trim() ||
		params.CallSid?.trim() ||
		"";
	const digits = params.Digits?.trim() ?? "";
	const context = await getWhisperContext(env.ALLOWLIST_KV, sid);

	if (digits === "1") {
		if (context?.fromE164) {
			const callerPhone = context.fromE164;
			await Promise.all([
				setCallerRecord(
					env.ALLOWLIST_KV,
					callerPhone,
					env.CONTACT_HASH_SALT,
					"verified",
					"accepted_uncertain",
				),
				persistCallerRuleSafely(env, {
					phoneE164: callerPhone,
					status: "allowed",
					source: "whisper_accept",
					reason: "Accepted via Press 1",
					ttlSeconds: THIRTY_DAYS_SECONDS,
				}),
			]);
		}
		if (sid) {
			enqueueTelemetry(ctx, () =>
				updateCallProgress(env.CALL_LOGS_DB, sid, {
					furthestPhase: "BRIDGED",
					finalOutcome: "CONNECTED_UNCERTAIN_ACCEPTED",
					outcomeReason: "Accepted via Press 1",
				}),
			);
		}
		return buildAcceptBridgeTwiml();
	}

	if (digits === "2") {
		if (context?.fromE164) {
			const callerPhone = context.fromE164;
			await Promise.all([
				setCallerRecord(
					env.ALLOWLIST_KV,
					callerPhone,
					env.CONTACT_HASH_SALT,
					"blocked",
					"blocked_via_whisper",
					null,
				),
				persistCallerRuleSafely(env, {
					phoneE164: callerPhone,
					status: "blocked",
					source: "whisper_block",
					reason: "Blocked via Press 2",
					ttlSeconds: null,
				}),
			]);
		}
		if (sid) {
			enqueueTelemetry(ctx, () =>
				updateCallProgress(env.CALL_LOGS_DB, sid, {
					furthestPhase: "WHISPER",
					finalOutcome: "REJECTED_UNCERTAIN_BLOCKED",
					outcomeReason: "Blocked via Press 2",
				}),
			);
		}
		return buildHangupTwiml();
	}

	if (sid) {
		enqueueTelemetry(ctx, () =>
			updateCallProgress(env.CALL_LOGS_DB, sid, {
				furthestPhase: "WHISPER",
				finalOutcome: "REJECTED_UNCERTAIN_DISMISSED",
				outcomeReason: "Whisper dismissed without pressing 1",
			}),
		);
	}

	return buildHangupTwiml();
}

/**
 * Handles post-`<Dial>` completion so missed calls get voicemail while blocked calls drop silently.
 */
async function handleDialCompleteStep(
	env: CallFirewallEnv,
	params: Record<string, string>,
	ctx?: ExecutionWaitUntil,
): Promise<Response> {
	const callSid = params.CallSid?.trim() ?? "";
	const dialStatus = (params.DialCallStatus ?? "").trim().toLowerCase();
	const sipDurationSec = Math.max(
		0,
		Number.parseInt(params.DialCallDuration ?? "0", 10) || 0,
	);

	if (dialStatus === "completed") {
		if (callSid) {
			enqueueTelemetry(ctx, () =>
				updateCallProgress(env.CALL_LOGS_DB, callSid, { sipDurationSec }),
			);
		}
		return buildHangupTwiml();
	}

	const normalizedFrom = normalizePhoneNumber(params.From ?? "");
	if (normalizedFrom) {
		const rule = await lookupCallerRuleSafely(env, normalizedFrom);
		if (rule?.status === "blocked") {
			return buildHangupTwiml();
		}

		const status = await lookupCallerStatus(
			env.ALLOWLIST_KV,
			normalizedFrom,
			env.CONTACT_HASH_SALT,
		);
		if (status === "blocked") {
			return buildHangupTwiml();
		}
	}

	if (callSid) {
		enqueueTelemetry(ctx, () =>
			updateCallProgress(env.CALL_LOGS_DB, callSid, {
				furthestPhase: "VOICEMAIL",
				finalOutcome: "MISSED_VOICEMAIL",
				sipDurationSec,
				outcomeReason: `Unanswered (${dialStatus || "no-answer"}) -> voicemail`,
			}),
		);
	}

	return buildVoicemailTwiml(resolveOwnerName(env.OWNER_NAME), env.OWNER_NAME_IPA);
}

/**
 * Records terminal Twilio `StatusCallback` metrics and triggers 90-day call log retention pruning.
 */
function handleStatusCallback(
	env: CallFirewallEnv,
	params: Record<string, string>,
	ctx?: ExecutionWaitUntil,
): Response {
	const callSid = params.CallSid?.trim() ?? "";
	const fromNumber =
		normalizePhoneNumber(params.From ?? "") ?? (params.From?.trim() || "anonymous");
	const callStatus = params.CallStatus?.trim().toLowerCase() ?? "";
	const inboundDurationSec = Math.max(
		0,
		Number.parseInt(params.CallDuration ?? "0", 10) || 0,
	);

	if (callSid && TERMINAL_CALL_STATUSES.has(callStatus)) {
		enqueueTelemetry(ctx, async () => {
			await finalizeCallStatus(env.CALL_LOGS_DB, {
				callSid,
				fromNumber,
				inboundDurationSec,
				callStatus,
			});
			await pruneExpiredCallLogs(env.CALL_LOGS_DB, 90);
		});
	}

	return new Response(null, { status: 204 });
}

/**
 * Routes and authenticates all `/voice/*` webhooks coming from Twilio Programmable Voice.
 *
 * @param request - Incoming HTTP POST request.
 * @param env - Worker runtime bindings.
 * @param url - Parsed request URL.
 * @param ctx - Optional Worker execution context used for non-blocking D1 telemetry writes.
 * @returns TwiML XML response, `204` on `/voice/status`, or `403`/`405`/`404` on invalid requests.
 */
export async function handleVoiceRequest(
	request: Request,
	env: CallFirewallEnv,
	url: URL,
	ctx?: ExecutionWaitUntil,
): Promise<Response> {
	if (request.method !== "POST") {
		return new Response("Method Not Allowed", { status: 405 });
	}

	const params = await parseTwilioForm(request);
	const isAuthentic = await verifyTwilioRequest(request, params, env.TWILIO_AUTH_TOKEN);
	if (!isAuthentic) {
		return new Response("Forbidden", { status: 403 });
	}

	const origin = url.origin;

	switch (url.pathname) {
		case "/voice/incoming":
			return handleIncomingCall(env, origin, params, ctx);
		case "/voice/dtmf":
			return handleDtmfStep(env, origin, params, ctx);
		case "/voice/intent":
			return handleIntentStep(env, origin, url, params, ctx);
		case "/voice/whisper":
			return handleWhisperStep(env, origin, url, params);
		case "/voice/whisper-action":
			return handleWhisperActionStep(env, url, params, ctx);
		case "/voice/dial-complete":
			return handleDialCompleteStep(env, params, ctx);
		case "/voice/status":
			return handleStatusCallback(env, params, ctx);
		default:
			return new Response("Not Found", { status: 404 });
	}
}
