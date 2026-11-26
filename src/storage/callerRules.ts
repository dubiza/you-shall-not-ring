import { normalizePhoneNumber } from "../security/crypto.ts";
import type {
	CallerRuleRow,
	CallerRuleSource,
	CallerRuleStatus,
	CsvImportMode,
	CsvImportResult,
	D1Store,
} from "../types.ts";
import { ensureSchema } from "./callLogs.ts";

const CSV_IMPORT_CHUNK_SIZE = 10;
const EXISTING_CHECK_CHUNK_SIZE = 50;

const CALLER_RULE_SELECT_COLUMNS =
	"phone_e164, label, status, source, reason, created_at, updated_at, expires_at";

const PHONE_HEADER_EXACT = new Set([
	"phone",
	"number",
	"mobile",
	"tel",
	"telephone",
	"cell",
	"phone number",
	"mobile phone",
	"home phone",
	"work phone",
	"primary phone",
	"phone value",
]);

const FIRST_NAME_HEADERS = new Set(["first name", "given name", "firstname", "first"]);
const LAST_NAME_HEADERS = new Set(["last name", "family name", "lastname", "last"]);
const FULL_NAME_HEADERS = new Set([
	"name",
	"label",
	"contact",
	"full name",
	"display name",
	"contact name",
	"caller",
	"description",
]);

const FORMULA_TRIGGER_REGEX = /^(?:[\t\r\n]|[\s\u00A0]*[=+\-@])/;
const E164_PHONE_REGEX = /^\+[1-9]\d{6,14}$/;
const MAX_RULE_LABEL_CHARS = 120;
const MAX_RULE_REASON_CHARS = 160;

/**
 * Escapes SQL `LIKE` wildcard characters (`\`, `%`, `_`) so user search text matches literally.
 */
function escapeLikePattern(raw: string): string {
	return raw.replace(/[\\%_]/g, "\\$&");
}

/**
 * Sanitizes a caller rule label by stripping ASCII control characters, removing a single
 * CSV formula-escape leading apostrophe (for idempotent export/import round-trips), and
 * enforcing a 120-character cap.
 */
function sanitizeRuleLabel(raw: string): string {
	const cleaned = raw.replace(/[\x00-\x1F\x7F]+/g, " ").trim();
	const withoutExportPrefix = cleaned.replace(/^'(?=[\s\u00A0]*[=+\-@])/, "");
	return withoutExportPrefix.slice(0, MAX_RULE_LABEL_CHARS).trim();
}

/**
 * Escapes a single cell value according to RFC-4180 CSV rules while neutralizing spreadsheet
 * formula injection triggers (`=`, `+`, `-`, `@`, `\t`, `\r`, `\n`) on non-E.164 fields.
 *
 * Why exempt canonical E.164 numbers: Valid phone numbers like `+14155550102` begin with `+`
 * followed strictly by 7–15 digits, cannot execute spreadsheet formulas, and must round-trip
 * cleanly on CSV re-import.
 */
function escapeCsvField(value: string, options?: { allowLeadingPlusE164?: boolean }): string {
	const isSafeE164 = Boolean(options?.allowLeadingPlusE164 && E164_PHONE_REGEX.test(value));
	const safeValue = !isSafeE164 && FORMULA_TRIGGER_REGEX.test(value) ? `'${value}` : value;
	if (/[",\r\n]/.test(safeValue)) {
		return `"${safeValue.replace(/"/g, '""')}"`;
	}
	return safeValue;
}

/**
 * Normalizes a CSV header string for case- and punctuation-insensitive column matching.
 */
function normalizeHeaderName(raw: string): string {
	return raw
		.trim()
		.toLowerCase()
		.replace(/[_-]+/g, " ")
		.replace(/\s+/g, " ");
}

/**
 * Determines whether a normalized header represents a phone value column (excluding type/label columns).
 */
function isPhoneHeader(normalizedHeader: string): boolean {
	if (PHONE_HEADER_EXACT.has(normalizedHeader)) {
		return true;
	}
	if (/\b(type|label)\b/.test(normalizedHeader)) {
		return false;
	}
	return /\b(phone|mobile|tel|telephone|cell)\b/.test(normalizedHeader);
}

/**
 * Parses raw RFC-4180 CSV text (supporting quoted fields, escaped quotes, CRLF/LF, and UTF-8 BOM)
 * into raw string rows.
 */
function parseRfc4180Rows(csvText: string): string[][] {
	const text = csvText.startsWith("\uFEFF") ? csvText.slice(1) : csvText;
	const rows: string[][] = [];
	let currentRow: string[] = [];
	let currentField = "";
	let inQuotes = false;

	for (let i = 0; i < text.length; i += 1) {
		const ch = text[i] ?? "";

		if (inQuotes) {
			if (ch === '"') {
				if (text[i + 1] === '"') {
					currentField += '"';
					i += 1;
				} else {
					inQuotes = false;
				}
			} else {
				currentField += ch;
			}
			continue;
		}

		if (ch === '"' && currentField.length === 0) {
			inQuotes = true;
			continue;
		}

		if (ch === ",") {
			currentRow.push(currentField);
			currentField = "";
			continue;
		}

		if (ch === "\r" || ch === "\n") {
			if (ch === "\r" && text[i + 1] === "\n") {
				i += 1;
			}
			currentRow.push(currentField);
			currentField = "";
			if (currentRow.some((cell) => cell.trim().length > 0)) {
				rows.push(currentRow);
			}
			currentRow = [];
			continue;
		}

		currentField += ch;
	}

	if (currentField.length > 0 || currentRow.length > 0) {
		currentRow.push(currentField);
		if (currentRow.some((cell) => cell.trim().length > 0)) {
			rows.push(currentRow);
		}
	}

	return rows;
}

/**
 * Looks up an active (non-expired) caller rule in `caller_rules` by canonical E.164 number.
 *
 * @param db - Bound D1 or SQLite test database.
 * @param normalizedE164 - Canonical E.164 phone number.
 * @returns Active {@link CallerRuleRow} or `null` if absent/expired.
 */
export async function lookupCallerRule(
	db: D1Store,
	normalizedE164: string,
): Promise<CallerRuleRow | null> {
	await ensureSchema(db);
	const nowIso = new Date().toISOString();

	return db
		.prepare(
			`SELECT ${CALLER_RULE_SELECT_COLUMNS}
			 FROM caller_rules
			 WHERE phone_e164 = ? AND (expires_at IS NULL OR expires_at > ?)`,
		)
		.bind(normalizedE164, nowIso)
		.first<CallerRuleRow>();
}

/**
 * Inserts or updates a caller allow/block rule in `caller_rules`.
 *
 * Why preserve existing non-empty `label` when `input.label` is omitted: Automated call paths
 * (such as pressing 1 or 2 during a whisper screen) promote or block a caller without knowing
 * their contact name, so existing labels from CSV/manual entries must not be wiped out.
 *
 * @param db - Bound D1 or SQLite test database.
 * @param input - Rule fields and optional expiration TTL in seconds (`null`/omitted = permanent).
 * @returns The persisted {@link CallerRuleRow}.
 */
export async function upsertCallerRule(
	db: D1Store,
	input: {
		phoneE164: string;
		label?: string;
		status: CallerRuleStatus;
		source: CallerRuleSource;
		reason?: string;
		ttlSeconds?: number | null;
	},
): Promise<CallerRuleRow> {
	await ensureSchema(db);
	const nowMs = Date.now();
	const nowIso = new Date(nowMs).toISOString();
	const expiresAt =
		input.ttlSeconds !== undefined && input.ttlSeconds !== null && input.ttlSeconds > 0
			? new Date(nowMs + input.ttlSeconds * 1000).toISOString()
			: null;

	const cleanLabel = input.label !== undefined ? sanitizeRuleLabel(input.label) : "";
	const cleanReason =
		input.reason !== undefined
			? input.reason.replace(/[\x00-\x1F\x7F]+/g, " ").trim().slice(0, MAX_RULE_REASON_CHARS)
			: "";

	await db
		.prepare(
			`INSERT INTO caller_rules (
				phone_e164,
				label,
				status,
				source,
				reason,
				created_at,
				updated_at,
				expires_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(phone_e164) DO UPDATE SET
				label = CASE WHEN ? = 1 AND excluded.label != '' THEN excluded.label ELSE caller_rules.label END,
				status = excluded.status,
				source = excluded.source,
				reason = CASE WHEN ? = 1 THEN excluded.reason ELSE caller_rules.reason END,
				updated_at = excluded.updated_at,
				expires_at = excluded.expires_at`,
		)
		.bind(
			input.phoneE164,
			cleanLabel,
			input.status,
			input.source,
			cleanReason,
			nowIso,
			nowIso,
			expiresAt,
			input.label !== undefined ? 1 : 0,
			input.reason !== undefined ? 1 : 0,
		)
		.run();

	const saved = await db
		.prepare(`SELECT ${CALLER_RULE_SELECT_COLUMNS} FROM caller_rules WHERE phone_e164 = ?`)
		.bind(input.phoneE164)
		.first<CallerRuleRow>();

	if (!saved) {
		throw new Error(`Failed to read back caller rule for ${input.phoneE164}`);
	}

	return saved;
}

/**
 * Deletes a caller rule by canonical E.164 phone number.
 *
 * Why check existence before deleting: Neither `D1Store` nor `SqliteD1Store` exposes SQLite's
 * changed-row count consistently in `D1RunResult`, so pre-checking guarantees an accurate boolean.
 *
 * @param db - Bound D1 or SQLite test database.
 * @param phoneE164 - Canonical E.164 phone number.
 * @returns `true` if a matching row existed and was deleted.
 */
export async function deleteCallerRule(db: D1Store, phoneE164: string): Promise<boolean> {
	await ensureSchema(db);

	const existing = await db
		.prepare("SELECT 1 AS found FROM caller_rules WHERE phone_e164 = ?")
		.bind(phoneE164)
		.first<{ found: number }>();

	if (!existing) {
		return false;
	}

	await db.prepare("DELETE FROM caller_rules WHERE phone_e164 = ?").bind(phoneE164).run();
	return true;
}

/**
 * Lists active (non-expired) caller rules ordered by most recently updated first.
 *
 * @param db - Bound D1 or SQLite test database.
 * @param filter - Optional status and substring search filter.
 * @returns Active {@link CallerRuleRow} entries.
 */
export async function listCallerRules(
	db: D1Store,
	filter?: { status?: CallerRuleStatus; search?: string },
): Promise<CallerRuleRow[]> {
	await ensureSchema(db);
	const nowIso = new Date().toISOString();

	const conditions: string[] = ["(expires_at IS NULL OR expires_at > ?)"];
	const params: unknown[] = [nowIso];

	if (filter?.status) {
		conditions.push("status = ?");
		params.push(filter.status);
	}

	const search = filter?.search?.trim();
	if (search) {
		const pattern = `%${escapeLikePattern(search)}%`;
		conditions.push(
			`(phone_e164 LIKE ? ESCAPE '\\'
			  OR label LIKE ? ESCAPE '\\'
			  OR reason LIKE ? ESCAPE '\\')`,
		);
		params.push(pattern, pattern, pattern);
	}

	const result = await db
		.prepare(
			`SELECT ${CALLER_RULE_SELECT_COLUMNS}
			 FROM caller_rules
			 WHERE ${conditions.join(" AND ")}
			 ORDER BY updated_at DESC, phone_e164 ASC`,
		)
		.bind(...params)
		.all<CallerRuleRow>();

	return result.results ?? [];
}

/**
 * Parses contact CSV text into deduplicated E.164 phone + label pairs.
 *
 * Supports RFC-4180 quoting, CRLF/LF line endings, optional headers (including Google/Apple
 * Contacts `First Name` + `Last Name` + `Phone 1 - Value` / `Mobile`), 1-column phone lists,
 * and headerless `phone,label` CSVs. Deduplicates by `phoneE164` keeping the latest non-empty label.
 *
 * @param csvText - Raw CSV string uploaded or pasted by the user.
 * @returns Valid deduplicated rows and count of invalid/non-dialable entries skipped.
 */
export function parseContactsCsv(csvText: string): {
	rows: Array<{ phoneE164: string; label: string }>;
	skippedInvalid: number;
} {
	const rawRows = parseRfc4180Rows(csvText);
	if (rawRows.length === 0) {
		return { rows: [], skippedInvalid: 0 };
	}

	const firstRow = rawRows[0] ?? [];
	const normalizedHeaders = firstRow.map(normalizeHeaderName);

	const phoneCols: number[] = [];
	let firstNameCol = -1;
	let lastNameCol = -1;
	let fullNameCol = -1;

	for (let idx = 0; idx < normalizedHeaders.length; idx += 1) {
		const header = normalizedHeaders[idx] ?? "";
		if (isPhoneHeader(header)) {
			phoneCols.push(idx);
		} else if (FIRST_NAME_HEADERS.has(header) && firstNameCol === -1) {
			firstNameCol = idx;
		} else if (LAST_NAME_HEADERS.has(header) && lastNameCol === -1) {
			lastNameCol = idx;
		} else if (FULL_NAME_HEADERS.has(header) && fullNameCol === -1) {
			fullNameCol = idx;
		}
	}

	const firstRowHasPhoneValue = firstRow.some((cell) => normalizePhoneNumber(cell) !== null);
	const hasHeader =
		!firstRowHasPhoneValue &&
		(phoneCols.length > 0 || firstNameCol !== -1 || lastNameCol !== -1 || fullNameCol !== -1);

	const dataStartIndex = hasHeader ? 1 : 0;
	const deduped = new Map<string, string>();
	let skippedInvalid = 0;

	for (let rowIdx = dataStartIndex; rowIdx < rawRows.length; rowIdx += 1) {
		const row = rawRows[rowIdx] ?? [];

		if (!hasHeader) {
			const rawPhone = (row[0] ?? "").trim();
			const label = sanitizeRuleLabel(row[1] ?? "");
			const normalized = normalizePhoneNumber(rawPhone);
			if (!normalized) {
				skippedInvalid += 1;
				continue;
			}
			const existingLabel = deduped.get(normalized);
			if (existingLabel === undefined || label.length > 0) {
				deduped.set(normalized, label);
			}
			continue;
		}

		const firstName = firstNameCol !== -1 ? (row[firstNameCol] ?? "").trim() : "";
		const lastName = lastNameCol !== -1 ? (row[lastNameCol] ?? "").trim() : "";
		const combinedName = [firstName, lastName].filter((part) => part.length > 0).join(" ");
		const fallbackName = fullNameCol !== -1 ? (row[fullNameCol] ?? "").trim() : "";
		const label = sanitizeRuleLabel(combinedName.length > 0 ? combinedName : fallbackName);

		const targetPhoneCols = phoneCols.length > 0 ? phoneCols : [0];
		if (targetPhoneCols.length === 1) {
			const colIndex = targetPhoneCols[0] ?? 0;
			const rawPhone = (row[colIndex] ?? "").trim();
			const normalized = normalizePhoneNumber(rawPhone);
			if (!normalized) {
				skippedInvalid += 1;
				continue;
			}
			const existingLabel = deduped.get(normalized);
			if (existingLabel === undefined || label.length > 0) {
				deduped.set(normalized, label);
			}
			continue;
		}

		// Multi-phone contact exports (e.g. Google Contacts Phone 1 / Phone 2): import every populated valid number.
		let rowHadAnyPhoneCandidate = false;
		for (const colIndex of targetPhoneCols) {
			const rawPhone = (row[colIndex] ?? "").trim();
			if (!rawPhone) {
				continue;
			}
			rowHadAnyPhoneCandidate = true;
			const normalized = normalizePhoneNumber(rawPhone);
			if (!normalized) {
				skippedInvalid += 1;
				continue;
			}
			const existingLabel = deduped.get(normalized);
			if (existingLabel === undefined || label.length > 0) {
				deduped.set(normalized, label);
			}
		}

		if (!rowHadAnyPhoneCandidate) {
			skippedInvalid += 1;
		}
	}

	const rows = Array.from(deduped.entries()).map(([phoneE164, label]) => ({
		phoneE164,
		label,
	}));

	return { rows, skippedInvalid };
}

/**
 * Bulk-imports contacts from CSV into D1 `caller_rules` in D1-safe multi-row upsert chunks.
 *
 * Why chunks of at most 10 rows (80 bound parameters): Cloudflare D1 enforces a hard limit of
 * 100 bound parameters per prepared SQL statement; 10 rows * 8 columns stays strictly below 100.
 *
 * @param db - Bound D1 or SQLite test database.
 * @param csvText - Raw CSV text.
 * @param mode - `"merge"` keeps existing CSV rules; `"replace_csv"` deletes prior `source = 'csv'` rules first.
 * @returns Import summary counts (`imported`, `updated`, `skippedInvalid`, `mode`).
 */
export async function importCallerRulesCsv(
	db: D1Store,
	csvText: string,
	mode: CsvImportMode,
): Promise<CsvImportResult> {
	await ensureSchema(db);
	const { rows, skippedInvalid } = parseContactsCsv(csvText);

	if (mode === "replace_csv") {
		await db.prepare("DELETE FROM caller_rules WHERE source = 'csv' AND status != 'blocked'").run();
	}

	if (rows.length === 0) {
		return {
			imported: 0,
			updated: 0,
			skippedInvalid,
			mode,
		};
	}

	const blockedPhones = new Set<string>();
	const existingAllowedPhones = new Set<string>();
	for (let i = 0; i < rows.length; i += EXISTING_CHECK_CHUNK_SIZE) {
		const chunk = rows.slice(i, i + EXISTING_CHECK_CHUNK_SIZE);
		const placeholders = chunk.map(() => "?").join(", ");
		const result = await db
			.prepare(`SELECT phone_e164, status FROM caller_rules WHERE phone_e164 IN (${placeholders})`)
			.bind(...chunk.map((item) => item.phoneE164))
			.all<{ phone_e164: string; status: CallerRuleStatus }>();

		for (const existingRow of result.results ?? []) {
			if (existingRow.status === "blocked") {
				blockedPhones.add(existingRow.phone_e164);
			} else {
				existingAllowedPhones.add(existingRow.phone_e164);
			}
		}
	}

	// Never let bulk CSV contact imports unblock a number that was explicitly blocked.
	const rowsToUpsert = rows.filter((row) => !blockedPhones.has(row.phoneE164));

	if (rowsToUpsert.length === 0) {
		return {
			imported: 0,
			updated: 0,
			skippedInvalid,
			mode,
		};
	}

	let imported = 0;
	let updated = 0;
	for (const row of rowsToUpsert) {
		if (existingAllowedPhones.has(row.phoneE164)) {
			updated += 1;
		} else {
			imported += 1;
		}
	}

	const nowIso = new Date().toISOString();

	for (let i = 0; i < rowsToUpsert.length; i += CSV_IMPORT_CHUNK_SIZE) {
		const chunk = rowsToUpsert.slice(i, i + CSV_IMPORT_CHUNK_SIZE);
		const valuesSql = chunk.map(() => "(?, ?, ?, ?, ?, ?, ?, ?)").join(", ");
		const params: unknown[] = [];

		for (const item of chunk) {
			params.push(
				item.phoneE164,
				item.label,
				"allowed",
				"csv",
				"CSV contacts import",
				nowIso,
				nowIso,
				null,
			);
		}

		await db
			.prepare(
				`INSERT INTO caller_rules (
					phone_e164,
					label,
					status,
					source,
					reason,
					created_at,
					updated_at,
					expires_at
				) VALUES ${valuesSql}
				ON CONFLICT(phone_e164) DO UPDATE SET
					label = CASE WHEN excluded.label != '' THEN excluded.label ELSE caller_rules.label END,
					status = excluded.status,
					source = excluded.source,
					reason = excluded.reason,
					updated_at = excluded.updated_at,
					expires_at = excluded.expires_at
				WHERE caller_rules.status != 'blocked'`,
			)
			.bind(...params)
			.run();
	}

	return {
		imported,
		updated,
		skippedInvalid,
		mode,
	};
}

/**
 * Exports all active (non-expired) caller rules as an RFC-4180 CSV document.
 *
 * @param db - Bound D1 or SQLite test database.
 * @returns RFC-4180 CSV string with header `phone,label,status,source,expires_at`.
 */
export async function exportCallerRulesCsv(db: D1Store): Promise<string> {
	const rules = await listCallerRules(db);
	const lines = ["phone,label,status,source,expires_at"];

	for (const rule of rules) {
		lines.push(
			[
				escapeCsvField(rule.phone_e164, { allowLeadingPlusE164: true }),
				escapeCsvField(rule.label),
				escapeCsvField(rule.status),
				escapeCsvField(rule.source),
				escapeCsvField(rule.expires_at ?? ""),
			].join(","),
		);
	}

	return lines.join("\r\n");
}
