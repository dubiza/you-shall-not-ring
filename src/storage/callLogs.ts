import type {
	CallLogRow,
	CallOutcome,
	CallPhase,
	CallerStatus,
	D1Store,
	DashboardPeriod,
	DashboardSummary,
} from "../types.ts";

const SCHEMA_STATEMENTS: readonly string[] = [
	`CREATE TABLE IF NOT EXISTS call_logs (
	call_sid TEXT PRIMARY KEY,
	from_number TEXT NOT NULL,
	caller_trust TEXT NOT NULL DEFAULT 'unknown',
	started_at TEXT NOT NULL,
	ended_at TEXT,
	furthest_phase TEXT NOT NULL,
	final_outcome TEXT NOT NULL,
	expected_digit TEXT,
	pressed_digit TEXT,
	speech_attempts INTEGER NOT NULL DEFAULT 0,
	transcript TEXT,
	ai_decision TEXT,
	ai_category TEXT,
	ai_confidence REAL,
	prompt_injection_score REAL,
	outcome_reason TEXT,
	inbound_duration_sec INTEGER NOT NULL DEFAULT 0,
	sip_duration_sec INTEGER NOT NULL DEFAULT 0,
	estimated_cost_cents REAL NOT NULL DEFAULT 0
)`,
	"CREATE INDEX IF NOT EXISTS idx_call_logs_started_at ON call_logs(started_at DESC)",
	"CREATE INDEX IF NOT EXISTS idx_call_logs_outcome ON call_logs(final_outcome)",
	"CREATE INDEX IF NOT EXISTS idx_call_logs_from_number ON call_logs(from_number)",
	`CREATE TABLE IF NOT EXISTS caller_rules (
	phone_e164 TEXT PRIMARY KEY,
	label TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL CHECK (status IN ('allowed', 'blocked')),
	source TEXT NOT NULL,
	reason TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	expires_at TEXT
)`,
	"CREATE INDEX IF NOT EXISTS idx_caller_rules_status ON caller_rules(status)",
];

const initializedDatabases = new WeakSet<D1Store>();
const pendingSchemaInits = new WeakMap<D1Store, Promise<void>>();

const INBOUND_CENTS_PER_MINUTE = 0.85;
const SIP_CENTS_PER_MINUTE = 0.4;
const SPEECH_CENTS_PER_ATTEMPT = 2.0;

/**
 * Ensures the D1 schema (`call_logs`, `caller_rules`, and indexes) exists idempotently.
 *
 * Why execute one statement per `prepare(...).run()` and cache per `D1Store` instance:
 * Running each DDL statement individually works identically on both Cloudflare D1 and
 * `SqliteD1Store`, while the `WeakSet` avoids redundant schema round-trips per isolate.
 *
 * @param db - Bound D1 or SQLite test database.
 */
export async function ensureSchema(db: D1Store): Promise<void> {
	if (initializedDatabases.has(db)) {
		return;
	}

	const inFlight = pendingSchemaInits.get(db);
	if (inFlight) {
		return inFlight;
	}

	const initPromise = (async () => {
		for (const statement of SCHEMA_STATEMENTS) {
			await db.prepare(statement).run();
		}
		initializedDatabases.add(db);
	})();

	pendingSchemaInits.set(db, initPromise);
	try {
		await initPromise;
	} finally {
		pendingSchemaInits.delete(db);
	}
}

/**
 * Calculates estimated Twilio programmable voice + speech recognition cost in US cents.
 *
 * Why rounded to 2 decimal places: Twilio bills voice legs in whole-minute increments
 * ($0.0085/min inbound, $0.0040/min SIP) plus $0.02 per speech gather turn; rounding avoids
 * floating-point accumulation drift in dashboard spend totals.
 *
 * @param params - Call duration legs (seconds) and speech recognition turns.
 * @returns Estimated cost in US cents rounded to 2 decimal places.
 */
export function calculateCallCostCents(params: {
	inboundDurationSec: number;
	sipDurationSec: number;
	speechAttempts: number;
}): number {
	const inboundSec = Number.isFinite(params.inboundDurationSec)
		? Math.max(0, params.inboundDurationSec)
		: 0;
	const sipSec = Number.isFinite(params.sipDurationSec) ? Math.max(0, params.sipDurationSec) : 0;
	const speechAttempts = Number.isFinite(params.speechAttempts)
		? Math.max(0, params.speechAttempts)
		: 0;

	const inboundCents =
		inboundSec > 0 ? Math.ceil(inboundSec / 60) * INBOUND_CENTS_PER_MINUTE : 0;
	const sipCents = sipSec > 0 ? Math.ceil(sipSec / 60) * SIP_CENTS_PER_MINUTE : 0;
	const speechCents = speechAttempts * SPEECH_CENTS_PER_ATTEMPT;

	const total = inboundCents + sipCents + speechCents;
	return Math.round(total * 100) / 100;
}

/**
 * Inserts or updates the initial telemetry record for an incoming call.
 *
 * @param db - Bound D1 or SQLite test database.
 * @param input - Initial call metadata captured at `/voice/incoming`.
 */
export async function upsertCallStart(
	db: D1Store,
	input: {
		callSid: string;
		fromNumber: string;
		callerTrust: CallerStatus;
		furthestPhase: CallPhase;
		finalOutcome: CallOutcome;
		expectedDigit?: string;
		outcomeReason?: string;
	},
): Promise<void> {
	await ensureSchema(db);
	const startedAt = new Date().toISOString();

	await db
		.prepare(
			`INSERT INTO call_logs (
				call_sid,
				from_number,
				caller_trust,
				started_at,
				furthest_phase,
				final_outcome,
				expected_digit,
				outcome_reason
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(call_sid) DO UPDATE SET
				from_number = excluded.from_number,
				caller_trust = excluded.caller_trust,
				furthest_phase = excluded.furthest_phase,
				final_outcome = excluded.final_outcome,
				expected_digit = COALESCE(excluded.expected_digit, call_logs.expected_digit),
				outcome_reason = COALESCE(excluded.outcome_reason, call_logs.outcome_reason)`,
		)
		.bind(
			input.callSid,
			input.fromNumber,
			input.callerTrust,
			startedAt,
			input.furthestPhase,
			input.finalOutcome,
			input.expectedDigit ?? null,
			input.outcomeReason ?? null,
		)
		.run();
}

/**
 * Progress patch accepted by {@link updateCallProgress}.
 */
export type CallProgressPatch = Partial<{
	furthestPhase: CallPhase;
	finalOutcome: CallOutcome;
	pressedDigit: string;
	speechAttemptsIncrement: number;
	transcript: string;
	aiDecision: string;
	aiCategory: string;
	aiConfidence: number;
	promptInjectionScore: number;
	outcomeReason: string;
	sipDurationSec: number;
}>;

/**
 * Incrementally updates a call log row as the caller advances through screening phases.
 *
 * Why read existing leg metrics before updating: Only explicitly provided fields are modified,
 * preserving earlier non-null telemetry while allowing accurate cost recalculation when
 * `sipDurationSec` or `speechAttemptsIncrement` changes.
 *
 * @param db - Bound D1 or SQLite test database.
 * @param callSid - Twilio `CallSid` primary key.
 * @param patch - Subset of progress fields to update.
 */
export async function updateCallProgress(
	db: D1Store,
	callSid: string,
	patch: CallProgressPatch,
): Promise<void> {
	await ensureSchema(db);

	const existing = await db
		.prepare(
			"SELECT inbound_duration_sec, sip_duration_sec, speech_attempts FROM call_logs WHERE call_sid = ?",
		)
		.bind(callSid)
		.first<{
			inbound_duration_sec: number;
			sip_duration_sec: number;
			speech_attempts: number;
		}>();

	if (!existing) {
		console.warn(`updateCallProgress skipped: call_sid=${callSid} not found`);
		return;
	}

	const setClauses: string[] = [];
	const params: unknown[] = [];

	if (patch.furthestPhase !== undefined) {
		setClauses.push("furthest_phase = ?");
		params.push(patch.furthestPhase);
	}
	if (patch.finalOutcome !== undefined) {
		setClauses.push("final_outcome = ?");
		params.push(patch.finalOutcome);
	}
	if (patch.pressedDigit !== undefined) {
		setClauses.push("pressed_digit = ?");
		params.push(patch.pressedDigit);
	}
	if (patch.transcript !== undefined) {
		setClauses.push("transcript = ?");
		params.push(patch.transcript);
	}
	if (patch.aiDecision !== undefined) {
		setClauses.push("ai_decision = ?");
		params.push(patch.aiDecision);
	}
	if (patch.aiCategory !== undefined) {
		setClauses.push("ai_category = ?");
		params.push(patch.aiCategory);
	}
	if (patch.aiConfidence !== undefined) {
		setClauses.push("ai_confidence = ?");
		params.push(patch.aiConfidence);
	}
	if (patch.promptInjectionScore !== undefined) {
		setClauses.push("prompt_injection_score = ?");
		params.push(patch.promptInjectionScore);
	}
	if (patch.outcomeReason !== undefined) {
		setClauses.push("outcome_reason = ?");
		params.push(patch.outcomeReason);
	}

	const speechDelta =
		patch.speechAttemptsIncrement !== undefined && Number.isFinite(patch.speechAttemptsIncrement)
			? Math.max(0, Math.floor(patch.speechAttemptsIncrement))
			: undefined;

	if (speechDelta !== undefined) {
		setClauses.push("speech_attempts = speech_attempts + ?");
		params.push(speechDelta);
	}

	const nextSipDuration =
		patch.sipDurationSec !== undefined && Number.isFinite(patch.sipDurationSec)
			? Math.max(0, Math.round(patch.sipDurationSec))
			: undefined;

	if (nextSipDuration !== undefined) {
		setClauses.push("sip_duration_sec = ?");
		params.push(nextSipDuration);
	}

	if (speechDelta !== undefined || nextSipDuration !== undefined) {
		const updatedCost = calculateCallCostCents({
			inboundDurationSec: existing.inbound_duration_sec,
			sipDurationSec: nextSipDuration ?? existing.sip_duration_sec,
			speechAttempts: existing.speech_attempts + (speechDelta ?? 0),
		});
		setClauses.push("estimated_cost_cents = ?");
		params.push(updatedCost);
	}

	if (setClauses.length === 0) {
		return;
	}

	params.push(callSid);
	await db
		.prepare(`UPDATE call_logs SET ${setClauses.join(", ")} WHERE call_sid = ?`)
		.bind(...params)
		.run();
}

/**
 * Maps an `IN_PROGRESS` call's furthest phase to a deterministic abandoned outcome.
 */
function resolveAbandonedOutcome(
	furthestPhase: CallPhase,
	existingReason: string | null,
): { outcome: CallOutcome; reason: string | null } {
	switch (furthestPhase) {
		case "L2_DTMF":
			return {
				outcome: "STOPPED_L2_DTMF_ABANDONED",
				reason: "Hung up or timed out without pressing keypad digit",
			};
		case "L3_SPEECH":
			return {
				outcome: "STOPPED_L3_SILENCE",
				reason: "Hung up during speech prompt",
			};
		case "WHISPER":
			return {
				outcome: "REJECTED_UNCERTAIN_DISMISSED",
				reason: "Call ended before whisper acceptance",
			};
		case "BRIDGED":
			return {
				outcome: "CONNECTED_ALLOWLIST",
				reason: existingReason,
			};
		case "VOICEMAIL":
			return {
				outcome: "MISSED_VOICEMAIL",
				reason: existingReason,
			};
		case "L3_CLEF":
			return {
				outcome: "STOPPED_L3_SILENCE",
				reason: existingReason ?? "Hung up during AI screening",
			};
		case "L1_ALLOWLIST":
			return {
				outcome: "STOPPED_L2_DTMF_ABANDONED",
				reason: existingReason ?? "Call ended before screening completed",
			};
	}
}

/**
 * Finalizes a call record upon Twilio's terminal status callback (`/voice/status`).
 *
 * Why resolve `IN_PROGRESS` deterministically: Callers frequently hang up mid-prompt without
 * triggering `/voice/dtmf` or `/voice/intent`; converting `IN_PROGRESS` based on `furthest_phase`
 * guarantees accurate funnel attribution and final inbound billing totals.
 *
 * @param db - Bound D1 or SQLite test database.
 * @param input - Terminal call status metadata from Twilio.
 */
export async function finalizeCallStatus(
	db: D1Store,
	input: {
		callSid: string;
		fromNumber: string;
		inboundDurationSec: number;
		callStatus: string;
	},
): Promise<void> {
	await ensureSchema(db);

	const endedAt = new Date().toISOString();
	const inboundDurationSec = Number.isFinite(input.inboundDurationSec)
		? Math.max(0, Math.round(input.inboundDurationSec))
		: 0;

	const existing = await db
		.prepare(
			`SELECT furthest_phase, final_outcome, outcome_reason, speech_attempts, sip_duration_sec
			 FROM call_logs WHERE call_sid = ?`,
		)
		.bind(input.callSid)
		.first<{
			furthest_phase: CallPhase;
			final_outcome: CallOutcome;
			outcome_reason: string | null;
			speech_attempts: number;
			sip_duration_sec: number;
		}>();

	if (!existing) {
		const cost = calculateCallCostCents({
			inboundDurationSec,
			sipDurationSec: 0,
			speechAttempts: 0,
		});
		const reason = `Call ended before screening log initialization (${input.callStatus || "unknown"})`;

		await db
			.prepare(
				`INSERT INTO call_logs (
					call_sid,
					from_number,
					caller_trust,
					started_at,
					ended_at,
					furthest_phase,
					final_outcome,
					outcome_reason,
					inbound_duration_sec,
					sip_duration_sec,
					estimated_cost_cents
				) VALUES (?, ?, 'unknown', ?, ?, 'L2_DTMF', 'STOPPED_L2_DTMF_ABANDONED', ?, ?, 0, ?)`,
			)
			.bind(
				input.callSid,
				input.fromNumber,
				endedAt,
				endedAt,
				reason,
				inboundDurationSec,
				cost,
			)
			.run();
		return;
	}

	let finalOutcome = existing.final_outcome;
	let outcomeReason = existing.outcome_reason;

	if (existing.final_outcome === "IN_PROGRESS") {
		const resolved = resolveAbandonedOutcome(existing.furthest_phase, existing.outcome_reason);
		finalOutcome = resolved.outcome;
		outcomeReason = resolved.reason;
	}

	const updatedCost = calculateCallCostCents({
		inboundDurationSec,
		sipDurationSec: existing.sip_duration_sec,
		speechAttempts: existing.speech_attempts,
	});

	await db
		.prepare(
			`UPDATE call_logs
			 SET ended_at = ?,
				 inbound_duration_sec = ?,
				 final_outcome = ?,
				 outcome_reason = ?,
				 estimated_cost_cents = ?
			 WHERE call_sid = ?`,
		)
		.bind(endedAt, inboundDurationSec, finalOutcome, outcomeReason, updatedCost, input.callSid)
		.run();
}

/**
 * Deletes call logs older than the configured retention window (defaults to 90 days).
 *
 * @param db - Bound D1 or SQLite test database.
 * @param retentionDays - Number of days of history to retain.
 */
export async function pruneExpiredCallLogs(db: D1Store, retentionDays = 90): Promise<void> {
	await ensureSchema(db);
	const safeDays = Number.isFinite(retentionDays) ? Math.max(1, Math.floor(retentionDays)) : 90;
	const cutoffIso = new Date(Date.now() - safeDays * 86_400_000).toISOString();

	await db.prepare("DELETE FROM call_logs WHERE started_at < ?").bind(cutoffIso).run();
}

/**
 * Computes the lower-bound ISO UTC timestamp for a dashboard time window, or `null` for `"all"`.
 */
function getPeriodCutoffIso(period: DashboardPeriod): string | null {
	const now = new Date();
	switch (period) {
		case "7d":
			return new Date(now.getTime() - 7 * 86_400_000).toISOString();
		case "30d":
			return new Date(now.getTime() - 30 * 86_400_000).toISOString();
		case "month":
			return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0, 0)).toISOString();
		case "all":
			return null;
	}
}

/**
 * Escapes SQL `LIKE` wildcard characters (`\`, `%`, `_`) so user search text matches literally.
 */
function escapeLikePattern(raw: string): string {
	return raw.replace(/[\\%_]/g, "\\$&");
}

/**
 * Aggregates call screening effectiveness, outcome funnel counts, and Twilio spend metrics.
 *
 * @param db - Bound D1 or SQLite test database.
 * @param period - Reporting window (`7d`, `30d`, `month`, or `all`).
 * @returns Aggregated {@link DashboardSummary} metrics.
 */
export async function getDashboardSummary(
	db: D1Store,
	period: DashboardPeriod,
): Promise<DashboardSummary> {
	await ensureSchema(db);

	const cutoffIso = getPeriodCutoffIso(period);
	const whereClause = cutoffIso ? "WHERE started_at >= ?" : "";
	const params = cutoffIso ? [cutoffIso] : [];

	const aggRow = await db
		.prepare(
			`SELECT
				COUNT(*) AS total_calls,
				SUM(CASE WHEN final_outcome = 'BLOCKED_L1' THEN 1 ELSE 0 END) AS stopped_l1_blocked,
				SUM(CASE WHEN final_outcome = 'STOPPED_L2_DTMF_WRONG' THEN 1 ELSE 0 END) AS stopped_l2_wrong,
				SUM(CASE WHEN final_outcome = 'STOPPED_L2_DTMF_ABANDONED' THEN 1 ELSE 0 END) AS stopped_l2_abandoned,
				SUM(CASE WHEN final_outcome = 'STOPPED_L3_SILENCE' THEN 1 ELSE 0 END) AS stopped_l3_silence,
				SUM(CASE WHEN final_outcome = 'STOPPED_L3_AI_SPAM' THEN 1 ELSE 0 END) AS stopped_l3_ai_spam,
				SUM(CASE WHEN final_outcome IN ('REJECTED_UNCERTAIN_BLOCKED', 'REJECTED_UNCERTAIN_DISMISSED') THEN 1 ELSE 0 END) AS rejected_whisper,
				SUM(CASE WHEN final_outcome IN ('CONNECTED_ALLOWLIST', 'CONNECTED_AI_ALLOW', 'CONNECTED_UNCERTAIN_ACCEPTED') THEN 1 ELSE 0 END) AS reached_user,
				SUM(CASE WHEN final_outcome = 'MISSED_VOICEMAIL' THEN 1 ELSE 0 END) AS voicemail_count,
				SUM(CASE WHEN final_outcome = 'IN_PROGRESS' THEN 1 ELSE 0 END) AS in_progress_count,
				COALESCE(SUM(estimated_cost_cents), 0) AS usage_cost_cents
			FROM call_logs
			${whereClause}`,
		)
		.bind(...params)
		.first<{
			total_calls: number | null;
			stopped_l1_blocked: number | null;
			stopped_l2_wrong: number | null;
			stopped_l2_abandoned: number | null;
			stopped_l3_silence: number | null;
			stopped_l3_ai_spam: number | null;
			rejected_whisper: number | null;
			reached_user: number | null;
			voicemail_count: number | null;
			in_progress_count: number | null;
			usage_cost_cents: number | null;
		}>();

	const totalCalls = Number(aggRow?.total_calls ?? 0);
	const stoppedAtL1Blocked = Number(aggRow?.stopped_l1_blocked ?? 0);
	const stoppedAtL2Wrong = Number(aggRow?.stopped_l2_wrong ?? 0);
	const stoppedAtL2Abandoned = Number(aggRow?.stopped_l2_abandoned ?? 0);
	const stoppedAtL3Silence = Number(aggRow?.stopped_l3_silence ?? 0);
	const stoppedAtL3AiSpam = Number(aggRow?.stopped_l3_ai_spam ?? 0);
	const rejectedAtWhisper = Number(aggRow?.rejected_whisper ?? 0);

	const spamStoppedCount =
		stoppedAtL1Blocked +
		stoppedAtL2Wrong +
		stoppedAtL2Abandoned +
		stoppedAtL3Silence +
		stoppedAtL3AiSpam +
		rejectedAtWhisper;

	const spamStoppedPct =
		totalCalls > 0 ? Math.round((spamStoppedCount / totalCalls) * 1000) / 10 : 0;

	const reachedUserCount = Number(aggRow?.reached_user ?? 0);
	const voicemailCount = Number(aggRow?.voicemail_count ?? 0);
	const inProgressCount = Number(aggRow?.in_progress_count ?? 0);

	const usageCostCents = Math.round(Number(aggRow?.usage_cost_cents ?? 0) * 100) / 100;
	const fixedNumberCostCents = period === "7d" ? 27 : 115;
	const totalEstimatedCostCents = Math.round((usageCostCents + fixedNumberCostCents) * 100) / 100;

	const categoryQuery = await db
		.prepare(
			`SELECT COALESCE(ai_category, final_outcome) AS category, COUNT(*) AS count
			 FROM call_logs
			 ${whereClause}
			 GROUP BY COALESCE(ai_category, final_outcome)
			 ORDER BY count DESC, category ASC`,
		)
		.bind(...params)
		.all<{ category: string; count: number }>();

	const categoryBreakdown = (categoryQuery.results ?? []).map((row) => ({
		category: row.category,
		count: Number(row.count),
	}));

	return {
		period,
		totalCalls,
		spamStoppedCount,
		spamStoppedPct,
		stoppedAtL1Blocked,
		stoppedAtL2Wrong,
		stoppedAtL2Abandoned,
		stoppedAtL3Silence,
		stoppedAtL3AiSpam,
		rejectedAtWhisper,
		reachedUserCount,
		voicemailCount,
		inProgressCount,
		usageCostCents,
		fixedNumberCostCents,
		totalEstimatedCostCents,
		categoryBreakdown,
	};
}

/**
 * Lists paginated call logs joined with any matching `caller_rules.label`.
 *
 * @param db - Bound D1 or SQLite test database.
 * @param filter - Optional period, outcome, phase, text search, and pagination options.
 * @returns Paginated call log items with resolved `callerLabel` and total matching row count.
 */
export async function listCallLogs(
	db: D1Store,
	filter: {
		period?: DashboardPeriod;
		outcome?: string;
		phase?: string;
		search?: string;
		limit?: number;
		offset?: number;
	},
): Promise<{ items: Array<CallLogRow & { callerLabel: string | null }>; total: number }> {
	await ensureSchema(db);

	const limit =
		filter.limit !== undefined && Number.isFinite(filter.limit)
			? Math.min(200, Math.max(1, Math.floor(filter.limit)))
			: 50;
	const offset =
		filter.offset !== undefined && Number.isFinite(filter.offset)
			? Math.max(0, Math.floor(filter.offset))
			: 0;

	const conditions: string[] = [];
	const params: unknown[] = [];

	if (filter.period) {
		const cutoffIso = getPeriodCutoffIso(filter.period);
		if (cutoffIso) {
			conditions.push("call_logs.started_at >= ?");
			params.push(cutoffIso);
		}
	}

	const outcome = filter.outcome?.trim();
	if (outcome) {
		conditions.push("call_logs.final_outcome = ?");
		params.push(outcome);
	}

	const phase = filter.phase?.trim();
	if (phase) {
		conditions.push("call_logs.furthest_phase = ?");
		params.push(phase);
	}

	const search = filter.search?.trim();
	if (search) {
		const pattern = `%${escapeLikePattern(search)}%`;
		conditions.push(
			`(call_logs.from_number LIKE ? ESCAPE '\\'
			  OR COALESCE(call_logs.transcript, '') LIKE ? ESCAPE '\\'
			  OR COALESCE(call_logs.outcome_reason, '') LIKE ? ESCAPE '\\'
			  OR COALESCE(call_logs.ai_category, '') LIKE ? ESCAPE '\\'
			  OR COALESCE(caller_rules.label, '') LIKE ? ESCAPE '\\')`,
		);
		params.push(pattern, pattern, pattern, pattern, pattern);
	}

	const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
	const joinClause = "FROM call_logs LEFT JOIN caller_rules ON call_logs.from_number = caller_rules.phone_e164";

	const countRow = await db
		.prepare(`SELECT COUNT(*) AS total ${joinClause} ${whereClause}`)
		.bind(...params)
		.first<{ total: number | null }>();

	const total = Number(countRow?.total ?? 0);

	const rowsResult = await db
		.prepare(
			`SELECT
				call_logs.call_sid,
				call_logs.from_number,
				call_logs.caller_trust,
				call_logs.started_at,
				call_logs.ended_at,
				call_logs.furthest_phase,
				call_logs.final_outcome,
				call_logs.expected_digit,
				call_logs.pressed_digit,
				call_logs.speech_attempts,
				call_logs.transcript,
				call_logs.ai_decision,
				call_logs.ai_category,
				call_logs.ai_confidence,
				call_logs.prompt_injection_score,
				call_logs.outcome_reason,
				call_logs.inbound_duration_sec,
				call_logs.sip_duration_sec,
				call_logs.estimated_cost_cents,
				caller_rules.label AS caller_label
			 ${joinClause}
			 ${whereClause}
			 ORDER BY call_logs.started_at DESC
			 LIMIT ? OFFSET ?`,
		)
		.bind(...params, limit, offset)
		.all<CallLogRow & { caller_label: string | null }>();

	const items = (rowsResult.results ?? []).map((row) => {
		const { caller_label, ...callLog } = row;
		return {
			...callLog,
			callerLabel: caller_label && caller_label.length > 0 ? caller_label : null,
		};
	});

	return { items, total };
}
