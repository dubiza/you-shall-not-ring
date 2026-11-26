CREATE TABLE IF NOT EXISTS call_logs (
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
);

CREATE INDEX IF NOT EXISTS idx_call_logs_started_at ON call_logs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_call_logs_outcome ON call_logs(final_outcome);
CREATE INDEX IF NOT EXISTS idx_call_logs_from_number ON call_logs(from_number);

CREATE TABLE IF NOT EXISTS caller_rules (
	phone_e164 TEXT PRIMARY KEY,
	label TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL CHECK (status IN ('allowed', 'blocked')),
	source TEXT NOT NULL,
	reason TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	expires_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_caller_rules_status ON caller_rules(status);
