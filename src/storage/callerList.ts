import { hashPhoneNumber, hashPhoneNumbersBatch, normalizePhoneNumber } from "../security/crypto.ts";
import type {
	CallerRecord,
	CallerStatus,
	ContactsSnapshot,
	DtmfChallenge,
	IntentCategory,
	KvStore,
	WhisperContext,
} from "../types.ts";

const CONTACTS_SNAPSHOT_KEY = "contacts:snapshot";
const VERIFIED_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const CHALLENGE_TTL_SECONDS = 180;
const WHISPER_TTL_SECONDS = 180;

/**
 * Formats the per-caller override KV key from a salted phone hash.
 */
function callerRecordKey(phoneHash: string): string {
	return `caller:${phoneHash}`;
}

/**
 * Formats the short-lived DTMF challenge KV key for an active call.
 */
function challengeKey(callSid: string): string {
	return `challenge:${callSid}`;
}

/**
 * Formats the short-lived call whisper context KV key for an approved or uncertain call.
 */
function whisperKey(callSid: string): string {
	return `whisper:${callSid}`;
}

/**
 * Safely reads and validates the single-key device contacts snapshot from KV.
 */
async function readContactsSnapshot(kv: KvStore): Promise<ContactsSnapshot | null> {
	try {
		const raw = await kv.get<unknown>(CONTACTS_SNAPSHOT_KEY, "json");
		if (!raw || typeof raw !== "object") {
			return null;
		}
		const record = raw as Partial<ContactsSnapshot>;
		if (record.version !== 1 || !Array.isArray(record.hashes)) {
			return null;
		}
		const hashes = record.hashes.filter((item): item is string => typeof item === "string");
		return {
			version: 1,
			updatedAt: typeof record.updatedAt === "string" ? record.updatedAt : "",
			count: hashes.length,
			hashes,
		};
	} catch (error) {
		console.error("Failed to read contacts snapshot from KV", error);
		return null;
	}
}

/**
 * Returns non-identifying summary metadata for the synced iOS Contacts snapshot.
 *
 * @param kv - Bound Workers KV store.
 * @returns Count of synced contact hashes and last sync timestamp.
 */
export async function getContactsSnapshotMeta(
	kv: KvStore,
): Promise<{ count: number; updatedAt: string | null }> {
	const snapshot = await readContactsSnapshot(kv);
	if (!snapshot) {
		return { count: 0, updatedAt: null };
	}
	return {
		count: snapshot.count,
		updatedAt: snapshot.updatedAt || null,
	};
}

/**
 * Checks Layer 1 trust status for a normalized E.164 caller number.
 *
 * Lookup priority:
 * 1. Explicit `caller:{hash}` override (so blocking a synced contact still blocks them immediately).
 * 2. Single-key `contacts:snapshot` synced from iOS Shortcuts.
 * 3. Defaults to `"unknown"`.
 *
 * @param kv - Bound Workers KV store.
 * @param normalizedE164 - Canonical E.164 caller number.
 * @param salt - Configured `CONTACT_HASH_SALT`.
 * @returns Caller trust status.
 */
export async function lookupCallerStatus(
	kv: KvStore,
	normalizedE164: string,
	salt: string,
): Promise<CallerStatus> {
	const phoneHash = await hashPhoneNumber(normalizedE164, salt);

	const [overrideRaw, snapshot] = await Promise.all([
		kv.get<unknown>(callerRecordKey(phoneHash), "json"),
		readContactsSnapshot(kv),
	]);

	if (overrideRaw && typeof overrideRaw === "object") {
		const override = overrideRaw as Partial<CallerRecord>;
		if (override.status === "blocked") {
			return "blocked";
		}
		if (override.status === "verified") {
			return "verified";
		}
	}

	if (snapshot && snapshot.hashes.includes(phoneHash)) {
		return "contact";
	}

	return "unknown";
}

/**
 * Replaces the entire synced device contacts allowlist using exactly ONE KV write.
 *
 * Why a single-key snapshot: Cloudflare KV's Free Tier allows 1,000 writes/day. Writing
 * each contact individually would exhaust the daily write budget in two syncs, whereas a
 * single JSON blob uses 1 write per sync and atomically removes deleted contacts.
 *
 * @param kv - Bound Workers KV store.
 * @param rawNumbers - Unnormalized phone numbers exported from iPhone Contacts.
 * @param salt - Configured `CONTACT_HASH_SALT`.
 * @returns Sync summary counts and timestamp.
 */
export async function syncContactsSnapshot(
	kv: KvStore,
	rawNumbers: readonly string[],
	salt: string,
): Promise<{ syncedCount: number; skippedCount: number; updatedAt: string }> {
	const uniqueNormalized = new Set<string>();
	let skippedCount = 0;

	for (const raw of rawNumbers) {
		const normalized = normalizePhoneNumber(raw);
		if (normalized) {
			uniqueNormalized.add(normalized);
		} else if (raw.trim().length > 0) {
			skippedCount += 1;
		}
	}

	const hashes = await hashPhoneNumbersBatch(Array.from(uniqueNormalized), salt);

	const updatedAt = new Date().toISOString();
	const snapshot: ContactsSnapshot = {
		version: 1,
		updatedAt,
		count: hashes.length,
		hashes,
	};

	await kv.put(CONTACTS_SNAPSHOT_KEY, JSON.stringify(snapshot));

	return {
		syncedCount: hashes.length,
		skippedCount,
		updatedAt,
	};
}

/**
 * Stores a per-number verified or blocked record in KV.
 * Auto-verified strangers expire after 30 days; explicit blocks persist until deleted.
 *
 * @param kv - Bound Workers KV store.
 * @param normalizedE164 - Canonical E.164 phone number.
 * @param salt - Configured `CONTACT_HASH_SALT`.
 * @param status - `"verified"` or `"blocked"`.
 * @param reason - Optional audit note (never stored with raw phone PII).
 */
export async function setCallerRecord(
	kv: KvStore,
	normalizedE164: string,
	salt: string,
	status: "verified" | "blocked",
	reason?: string,
	ttlSeconds: number | null = VERIFIED_TTL_SECONDS,
): Promise<void> {
	const phoneHash = await hashPhoneNumber(normalizedE164, salt);
	const record: CallerRecord = {
		status,
		updatedAt: new Date().toISOString(),
		...(reason ? { reason } : {}),
	};

	const options =
		status === "verified" && ttlSeconds !== null
			? { expirationTtl: ttlSeconds }
			: undefined;

	await kv.put(callerRecordKey(phoneHash), JSON.stringify(record), options);
}

/**
 * Deletes an explicit verified/blocked override record for a phone number.
 */
export async function deleteCallerRecord(
	kv: KvStore,
	normalizedE164: string,
	salt: string,
): Promise<void> {
	const phoneHash = await hashPhoneNumber(normalizedE164, salt);
	await kv.delete(callerRecordKey(phoneHash));
}

/**
 * Saves the expected Layer 2 DTMF digit for an active `CallSid` with a 3-minute TTL.
 */
export async function saveDtmfChallenge(
	kv: KvStore,
	callSid: string,
	challenge: DtmfChallenge,
): Promise<void> {
	await kv.put(challengeKey(callSid), JSON.stringify(challenge), {
		expirationTtl: CHALLENGE_TTL_SECONDS,
	});
}

/**
 * Reads and immediately deletes a Layer 2 DTMF challenge so each call can attempt it once.
 */
export async function consumeDtmfChallenge(
	kv: KvStore,
	callSid: string,
): Promise<DtmfChallenge | null> {
	const key = challengeKey(callSid);
	try {
		const raw = await kv.get<unknown>(key, "json");
		await kv.delete(key);
		if (!raw || typeof raw !== "object") {
			return null;
		}
		const challenge = raw as Partial<DtmfChallenge>;
		if (typeof challenge.expectedDigit !== "string") {
			return null;
		}
		return {
			expectedDigit: challenge.expectedDigit,
			fromE164: typeof challenge.fromE164 === "string" ? challenge.fromE164 : null,
			createdAt: typeof challenge.createdAt === "string" ? challenge.createdAt : "",
		};
	} catch (error) {
		console.error("Failed to consume DTMF challenge from KV", error);
		return null;
	}
}

/**
 * Stores structured call whisper metadata in KV keyed by `CallSid` for interactive or auto-connect whispers.
 */
export async function saveWhisperContext(
	kv: KvStore,
	callSid: string,
	context: WhisperContext,
): Promise<void> {
	await kv.put(whisperKey(callSid), JSON.stringify(context), {
		expirationTtl: WHISPER_TTL_SECONDS,
	});
}

/**
 * Parses a raw KV whisper context payload into a validated {@link WhisperContext}.
 */
function parseWhisperContext(raw: unknown): WhisperContext | null {
	if (!raw || typeof raw !== "object") {
		return null;
	}
	const candidate = raw as Partial<WhisperContext>;
	if (
		typeof candidate.summary !== "string" ||
		(candidate.mode !== "auto" && candidate.mode !== "confirm")
	) {
		return null;
	}
	return {
		summary: candidate.summary,
		mode: candidate.mode,
		fromE164: typeof candidate.fromE164 === "string" ? candidate.fromE164 : null,
		category:
			typeof candidate.category === "string"
				? (candidate.category as IntentCategory)
				: "unclear",
	};
}

/**
 * Retrieves structured whisper metadata for a `CallSid`, returning `null` if missing or invalid.
 */
export async function getWhisperContext(
	kv: KvStore,
	callSid: string,
): Promise<WhisperContext | null> {
	if (!callSid) {
		return null;
	}
	try {
		const raw = await kv.get<unknown>(whisperKey(callSid), "json");
		return parseWhisperContext(raw);
	} catch (error) {
		console.error("Failed to fetch whisper context from KV", error);
		return null;
	}
}

/**
 * Reads and immediately deletes whisper metadata so interactive Press-1/Press-2 actions
 * execute at most once per `CallSid`.
 *
 * @param kv - Bound Workers KV store.
 * @param callSid - Twilio `CallSid` key.
 * @returns Validated {@link WhisperContext} or `null` if missing/already consumed.
 */
export async function consumeWhisperContext(
	kv: KvStore,
	callSid: string,
): Promise<WhisperContext | null> {
	if (!callSid) {
		return null;
	}
	const key = whisperKey(callSid);
	try {
		const raw = await kv.get<unknown>(key, "json");
		await kv.delete(key);
		return parseWhisperContext(raw);
	} catch (error) {
		console.error("Failed to consume whisper context from KV", error);
		return null;
	}
}
