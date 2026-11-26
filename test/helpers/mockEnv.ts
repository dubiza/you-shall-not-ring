import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { DatabaseSync, type SqliteInputValue } from "node:sqlite";
import { computeTwilioSignature } from "../../src/security/twilioSignature.ts";
import type {
	AiRunner,
	ClefResponse,
	D1RunResult,
	D1Statement,
	D1Store,
	ExecutionWaitUntil,
	IntentCategory,
	KvPutOptions,
	KvStore,
	CallFirewallEnv,
	SupportedClefModel,
} from "../../src/types.ts";

const MIGRATION_SQL = readFileSync(
	resolve(process.cwd(), "migrations/0001_init.sql"),
	"utf8",
);

/**
 * In-memory `KvStore` test double tracking read/write counters for Free Tier assertions.
 */
export class MockKvStore implements KvStore {
	private readonly store = new Map<string, string>();
	public putCount = 0;
	public deleteCount = 0;

	async get(key: string): Promise<string | null>;
	async get<ExpectedValue = unknown>(key: string, type: "json"): Promise<ExpectedValue | null>;
	async get<ExpectedValue = unknown>(
		key: string,
		type?: "json",
	): Promise<string | ExpectedValue | null> {
		const raw = this.store.get(key) ?? null;
		if (raw === null) {
			return null;
		}
		if (type === "json") {
			return JSON.parse(raw) as ExpectedValue;
		}
		return raw;
	}

	async put(key: string, value: string, _options?: KvPutOptions): Promise<void> {
		this.putCount += 1;
		this.store.set(key, value);
	}

	async delete(key: string): Promise<void> {
		this.deleteCount += 1;
		this.store.delete(key);
	}

	keys(): string[] {
		return Array.from(this.store.keys());
	}
}

/**
 * Converts arbitrary JS bind parameters into strict SQLite primitives.
 */
function toSqliteParam(value: unknown): SqliteInputValue {
	if (value === undefined || value === null) {
		return null;
	}
	if (
		typeof value === "string" ||
		typeof value === "number" ||
		typeof value === "bigint" ||
		value instanceof Uint8Array
	) {
		return value;
	}
	if (typeof value === "boolean") {
		return value ? 1 : 0;
	}
	return JSON.stringify(value);
}

/**
 * Prepared statement adapter wrapping Node's synchronous SQLite engine behind D1's async API.
 */
class SqliteD1Statement implements D1Statement {
	private readonly db: DatabaseSync;
	private readonly query: string;
	private readonly params: SqliteInputValue[];

	constructor(db: DatabaseSync, query: string, params: SqliteInputValue[] = []) {
		this.db = db;
		this.query = query;
		this.params = params;
	}

	bind(...values: unknown[]): D1Statement {
		return new SqliteD1Statement(this.db, this.query, values.map(toSqliteParam));
	}

	async first<T = Record<string, unknown>>(): Promise<T | null> {
		const stmt = this.db.prepare(this.query);
		const row = stmt.get(...this.params);
		return row ? ({ ...row } as T) : null;
	}

	async run<T = Record<string, unknown>>(): Promise<D1RunResult<T>> {
		// Multi-statement DDL (e.g. ensureSchema) uses exec when no parameters are bound.
		if (this.params.length === 0 && this.query.includes(";")) {
			this.db.exec(this.query);
			return { success: true, results: [] };
		}
		const stmt = this.db.prepare(this.query);
		stmt.run(...this.params);
		return { success: true, results: [] };
	}

	async all<T = Record<string, unknown>>(): Promise<D1RunResult<T>> {
		const stmt = this.db.prepare(this.query);
		const rows = stmt.all(...this.params);
		return {
			success: true,
			results: rows.map((row) => ({ ...row }) as T),
		};
	}
}

/**
 * Real SQLite-backed `D1Store` test double initialized with `migrations/0001_init.sql`.
 */
export class SqliteD1Store implements D1Store {
	public readonly sqlite: DatabaseSync;

	constructor(applyInitialMigration = true) {
		this.sqlite = new DatabaseSync(":memory:");
		if (applyInitialMigration) {
			this.sqlite.exec(MIGRATION_SQL);
		}
	}

	prepare(query: string): D1Statement {
		return new SqliteD1Statement(this.sqlite, query);
	}
}

/**
 * ExecutionContext test double that records `waitUntil` tasks so tests can `await flush()`.
 */
export class TestExecutionContext implements ExecutionWaitUntil {
	public readonly pending: Promise<unknown>[] = [];

	waitUntil(promise: Promise<unknown>): void {
		this.pending.push(promise);
	}

	async flush(): Promise<void> {
		await Promise.all(this.pending.splice(0, this.pending.length));
	}
}

/**
 * Recorded invocation captured by `MockAiRunner`.
 */
export interface RecordedAiCall {
	model: SupportedClefModel;
	inputs: Record<string, unknown>;
}

/**
 * Builds a structured Clef response object matching Cloudflare Workers AI output.
 */
export function buildClefResponse(options: {
	routingChoice: "allow" | "spam" | "uncertain";
	routingConfidence: number;
	categoryChoice: IntentCategory;
	injectionScore?: number;
}): ClefResponse {
	return {
		model: "clef",
		answers: {
			routing: {
				type: "choice",
				choice: options.routingChoice,
				probabilities: { [options.routingChoice]: options.routingConfidence },
				confidence: options.routingConfidence,
			},
			category: {
				type: "choice",
				choice: options.categoryChoice,
				probabilities: { [options.categoryChoice]: 0.9 },
				confidence: 0.9,
			},
			prompt_injection: {
				type: "noul",
				noul: options.injectionScore ?? 0.01,
			},
		},
		usage: {
			input_tokens: 140,
			output_tokens: 0,
		},
	};
}

/**
 * Configurable Cloudflare Clef Workers AI test double.
 */
export class MockAiRunner implements AiRunner {
	public readonly calls: RecordedAiCall[] = [];
	private readonly handler: (
		model: SupportedClefModel,
		inputs: Record<string, unknown>,
	) => Promise<unknown>;

	constructor(
		handler?: (model: SupportedClefModel, inputs: Record<string, unknown>) => Promise<unknown>,
	) {
		this.handler =
			handler ??
			(async () =>
				buildClefResponse({
					routingChoice: "uncertain",
					routingConfidence: 0.5,
					categoryChoice: "unclear",
				}));
	}

	async run(model: SupportedClefModel, inputs: Record<string, unknown>): Promise<unknown> {
		this.calls.push({ model, inputs });
		return this.handler(model, inputs);
	}
}

/**
 * Creates a deterministic test environment matching `CallFirewallEnv`.
 */
export function createTestEnv(overrides?: Partial<CallFirewallEnv>): {
	env: CallFirewallEnv;
	kv: MockKvStore;
	db: SqliteD1Store;
	ai: MockAiRunner;
	ctx: TestExecutionContext;
} {
	const kv = (overrides?.ALLOWLIST_KV as MockKvStore | undefined) ?? new MockKvStore();
	const db = (overrides?.CALL_LOGS_DB as SqliteD1Store | undefined) ?? new SqliteD1Store();
	const ai = (overrides?.AI as MockAiRunner | undefined) ?? new MockAiRunner();
	const ctx = new TestExecutionContext();

	const env: CallFirewallEnv = {
		ROUTING_MODE: "all",
		OWNER_NAME: "Siobhan",
		OWNER_NAME_IPA: "ʃəˈvɔːn",
		AI_MODEL: "@cf/cloudflare/clef",
		CF_ACCESS_TEAM_DOMAIN: "firewall-test.cloudflareaccess.com",
		ALLOWLIST_KV: kv,
		CALL_LOGS_DB: db,
		AI: ai,
		TWILIO_AUTH_TOKEN: "test-twilio-auth-token-12345",
		SIP_ENDPOINT: "sip:owner@firewall.sip.us1.twilio.com;transport=tls;secure=true",
		ADMIN_TOKEN: "test-admin-secret-token-abcdef",
		CONTACT_HASH_SALT: "test-contact-hash-salt-xyz",
		CF_ACCESS_AUD: "test-access-aud-12345",
		...overrides,
	};

	return { env, kv, db, ai, ctx };
}

/**
 * Builds a properly signed `POST` request mirroring Twilio Programmable Voice webhooks.
 */
export async function createSignedTwilioRequest(
	url: string,
	params: Record<string, string>,
	authToken: string,
	extraHeaders?: Record<string, string>,
): Promise<Request> {
	const signature = await computeTwilioSignature(url, params, authToken);
	const body = new URLSearchParams(params).toString();

	return new Request(url, {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			"X-Twilio-Signature": signature,
			...extraHeaders,
		},
		body,
	});
}
