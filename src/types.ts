/**
 * Routing mode controlling how the carrier forwards incoming calls to Twilio.
 * - `"all"`: Carrier unconditionally forwards every call (`*72`), so contacts bypass prompts in Workers KV.
 * - `"ccf"`: Carrier uses Conditional Call Forwarding for unknown/missed calls, so contacts ring natively first.
 */
export type RoutingMode = "all" | "ccf";

/**
 * Supported Cloudflare Workers AI Clef decision models.
 */
export type SupportedClefModel = "@cf/cloudflare/clef" | "@cf/cloudflare/clef-flash";

/**
 * Short selector parameter passed in the Clef request payload.
 */
export type ClefModelSelector = "clef" | "clef-flash";

/**
 * Binary yes/no probability question definition for Cloudflare Clef.
 */
export type ClefNoulQuestion = {
	type: "noul";
	instructions: string;
	criteria?: {
		true?: string;
		false?: string;
	};
};

/**
 * Multi-option classification question definition for Cloudflare Clef.
 */
export type ClefChoiceQuestion = {
	type: "choice";
	instructions: string;
	criteria: Record<string, string>;
};

/**
 * Supported Clef question variants.
 */
export type ClefQuestion = ClefNoulQuestion | ClefChoiceQuestion;

/**
 * Structured evaluation payload sent to Cloudflare's Clef decision model.
 */
export type ClefRequest = {
	model: ClefModelSelector;
	state: string;
	questions: Record<string, ClefQuestion>;
};

/**
 * Clef answer envelope for `choice` questions.
 */
export type ClefChoiceAnswer = {
	type: "choice";
	choice: string;
	probabilities: Record<string, number>;
	confidence: number;
};

/**
 * Clef answer envelope for `noul` (yes/no) questions.
 */
export type ClefNoulAnswer = {
	type: "noul";
	noul: number;
};

/**
 * Clef evaluation response returned by `env.AI.run`.
 */
export type ClefResponse = {
	model?: string;
	answers: Record<string, ClefChoiceAnswer | ClefNoulAnswer>;
	usage?: {
		input_tokens?: number;
		output_tokens?: number;
	};
};

/**
 * Minimal options subset passed when writing keys to Workers KV.
 */
export interface KvPutOptions {
	/** Absolute Unix timestamp (seconds) when the key expires. */
	expiration?: number;
	/** Relative lifetime (seconds) before automatic eviction. */
	expirationTtl?: number;
}

/**
 * Structural subset of Cloudflare `KVNamespace` used across storage helpers and unit tests.
 * Why a minimal interface: It keeps runtime bindings and in-memory test mocks 100% interchangeable without `any`.
 */
export interface KvStore {
	get(key: string): Promise<string | null>;
	get<ExpectedValue = unknown>(key: string, type: "json"): Promise<ExpectedValue | null>;
	put(key: string, value: string, options?: KvPutOptions): Promise<void>;
	delete(key: string): Promise<void>;
}

/**
 * Structural subset of Cloudflare's `Ai` binding for Clef inference and unit test doubles.
 */
export interface AiRunner {
	run(model: SupportedClefModel, inputs: Record<string, unknown>): Promise<unknown>;
}

/**
 * Minimal D1 query result shape shared between Cloudflare `D1Database` and SQLite test doubles.
 */
export interface D1RunResult<T = Record<string, unknown>> {
	results?: T[];
	success: boolean;
}

/**
 * Minimal prepared statement subset compatible with Cloudflare `D1PreparedStatement`.
 */
export interface D1Statement {
	bind(...values: unknown[]): D1Statement;
	first<T = Record<string, unknown>>(): Promise<T | null>;
	run<T = Record<string, unknown>>(): Promise<D1RunResult<T>>;
	all<T = Record<string, unknown>>(): Promise<D1RunResult<T>>;
}

/**
 * Minimal database subset compatible with Cloudflare `D1Database` without requiring `batch` covariance.
 */
export interface D1Store {
	prepare(query: string): D1Statement;
}

/**
 * Minimal execution context interface for non-blocking background telemetry via `waitUntil`.
 */
export interface ExecutionWaitUntil {
	waitUntil(promise: Promise<unknown>): void;
}

/**
 * Runtime bindings and secrets required by the You Shall Not Ring Worker.
 */
export interface CallFirewallEnv {
	ROUTING_MODE?: string;
	OWNER_NAME?: string;
	OWNER_NAME_IPA?: string;
	AI_MODEL?: string;
	CF_ACCESS_TEAM_DOMAIN?: string;
	ALLOWLIST_KV: KvStore;
	CALL_LOGS_DB: D1Store;
	AI: AiRunner;
	TWILIO_AUTH_TOKEN: string;
	SIP_ENDPOINT: string;
	ADMIN_TOKEN: string;
	CONTACT_HASH_SALT: string;
	CF_ACCESS_AUD: string;
}

/**
 * Trust classification returned by Layer 1 allowlist/blocklist lookup.
 */
export type CallerStatus = "contact" | "verified" | "blocked" | "unknown";

/**
 * Single-key KV payload containing salted phone hashes synced from the user's device Contacts.
 */
export interface ContactsSnapshot {
	version: 1;
	updatedAt: string;
	count: number;
	hashes: string[];
}

/**
 * Per-caller allow/block override record stored under `caller:{hash}`.
 */
export interface CallerRecord {
	status: "verified" | "blocked";
	updatedAt: string;
	reason?: string;
}

/**
 * Short-lived keypad verification challenge stored per incoming `CallSid`.
 */
export interface DtmfChallenge {
	expectedDigit: string;
	fromE164: string | null;
	createdAt: string;
}

/**
 * Normalized caller intent categories evaluated by Clef and fallback rules.
 */
export type IntentCategory =
	| "recruiter"
	| "buyer"
	| "delivery"
	| "appointment"
	| "personal"
	| "customer_service"
	| "local_service"
	| "billing"
	| "loan_scam"
	| "irs_scam"
	| "vendor_pitch"
	| "political_charity"
	| "ai_bot"
	| "spam_other"
	| "unclear";

/**
 * Three-way Layer 3 screening verdict returned by the Clef classifier or deterministic fallback.
 */
export interface IntentDecision {
	decision: "ALLOW" | "SPAM" | "UNCERTAIN";
	category: IntentCategory;
	confidence: number;
	promptInjectionScore: number;
	whisperSummary: string;
	reason: string;
	/** True when generated by deterministic keyword fallback rather than Clef. */
	fromFallback?: boolean;
}

/**
 * Short-lived whisper metadata stored per approved or uncertain call for `/voice/whisper` and `/voice/whisper-action`.
 */
export interface WhisperContext {
	summary: string;
	mode: "auto" | "confirm";
	fromE164: string | null;
	category: IntentCategory;
}

/**
 * Furthest pipeline stage reached by an incoming call.
 */
export type CallPhase =
	| "L1_ALLOWLIST"
	| "L2_DTMF"
	| "L3_SPEECH"
	| "L3_CLEF"
	| "WHISPER"
	| "BRIDGED"
	| "VOICEMAIL";

/**
 * Terminal or active disposition recorded in `call_logs.final_outcome`.
 */
export type CallOutcome =
	| "IN_PROGRESS"
	| "CONNECTED_ALLOWLIST"
	| "CONNECTED_AI_ALLOW"
	| "CONNECTED_UNCERTAIN_ACCEPTED"
	| "MISSED_VOICEMAIL"
	| "BLOCKED_L1"
	| "STOPPED_L2_DTMF_WRONG"
	| "STOPPED_L2_DTMF_ABANDONED"
	| "STOPPED_L3_SILENCE"
	| "STOPPED_L3_AI_SPAM"
	| "REJECTED_UNCERTAIN_BLOCKED"
	| "REJECTED_UNCERTAIN_DISMISSED";

/**
 * Persisted row stored in the D1 `call_logs` table.
 */
export interface CallLogRow {
	call_sid: string;
	from_number: string;
	caller_trust: string;
	started_at: string;
	ended_at: string | null;
	furthest_phase: CallPhase;
	final_outcome: CallOutcome;
	expected_digit: string | null;
	pressed_digit: string | null;
	speech_attempts: number;
	transcript: string | null;
	ai_decision: string | null;
	ai_category: string | null;
	ai_confidence: number | null;
	prompt_injection_score: number | null;
	outcome_reason: string | null;
	inbound_duration_sec: number;
	sip_duration_sec: number;
	estimated_cost_cents: number;
}

/**
 * Supported aggregation windows for the dashboard metrics summary.
 */
export type DashboardPeriod = "7d" | "30d" | "month" | "all";

/**
 * Aggregated call funnel and Twilio spend metrics returned by `GET /dashboard/api/summary`.
 */
export interface DashboardSummary {
	period: DashboardPeriod;
	totalCalls: number;
	spamStoppedCount: number;
	spamStoppedPct: number;
	stoppedAtL1Blocked: number;
	stoppedAtL2Wrong: number;
	stoppedAtL2Abandoned: number;
	stoppedAtL3Silence: number;
	stoppedAtL3AiSpam: number;
	rejectedAtWhisper: number;
	reachedUserCount: number;
	voicemailCount: number;
	inProgressCount: number;
	usageCostCents: number;
	fixedNumberCostCents: number;
	totalEstimatedCostCents: number;
	categoryBreakdown: Array<{ category: string; count: number }>;
}

/**
 * Rule enforcement status stored in `caller_rules`.
 */
export type CallerRuleStatus = "allowed" | "blocked";

/**
 * Origin of a rule stored in `caller_rules`.
 */
export type CallerRuleSource =
	| "csv"
	| "manual"
	| "auto_clef"
	| "whisper_accept"
	| "whisper_block"
	| "admin_api";

/**
 * Persisted allow/block rule stored in D1 `caller_rules`.
 */
export interface CallerRuleRow {
	phone_e164: string;
	label: string;
	status: CallerRuleStatus;
	source: CallerRuleSource;
	reason: string;
	created_at: string;
	updated_at: string;
	expires_at: string | null;
}

/**
 * Mode controlling how CSV imports interact with existing `source = 'csv'` rules.
 */
export type CsvImportMode = "merge" | "replace_csv";

/**
 * Summary returned after importing a CSV allowlist batch into D1.
 */
export interface CsvImportResult {
	imported: number;
	updated: number;
	skippedInvalid: number;
	mode: CsvImportMode;
}

/**
 * Verified identity extracted from a Cloudflare Zero Trust Access JWT.
 */
export interface AccessIdentity {
	email: string;
	sub: string;
}
