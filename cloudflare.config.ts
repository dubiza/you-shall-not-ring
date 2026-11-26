import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { bindings, defineConfig } from "cf/config";
import * as entrypoint from "./src/index.ts" with { type: "cf-worker" };

/**
 * Optional local deployment settings loaded from gitignored `local.config.json`.
 */
interface LocalConfig {
	workerName: string;
	d1DatabaseName: string;
	routingMode: "all" | "ccf";
	ownerName: string;
	ownerNameIpa: string;
	aiModel: "@cf/cloudflare/clef" | "@cf/cloudflare/clef-flash";
	cfAccessTeamDomain: string;
}

const DEFAULT_LOCAL_CONFIG: LocalConfig = {
	workerName: "you-shall-not-ring",
	d1DatabaseName: "you-shall-not-ring-db",
	routingMode: "all",
	ownerName: "Your Name",
	ownerNameIpa: "",
	aiModel: "@cf/cloudflare/clef",
	cfAccessTeamDomain: "",
};

/**
 * Loads personal instance settings from `local.config.json` when present, falling back to safe public defaults.
 *
 * Why a gitignored JSON override: Keeps personal Worker names, D1 database names, spoken-name IPA,
 * and Zero Trust team domains out of public version control while deploying from a single branch.
 */
function loadLocalConfig(): LocalConfig {
	const configPath = resolve(process.cwd(), "local.config.json");
	if (!existsSync(configPath)) {
		return DEFAULT_LOCAL_CONFIG;
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(readFileSync(configPath, "utf8"));
	} catch (error) {
		throw new Error(`Invalid JSON in ${configPath}: ${error instanceof Error ? error.message : String(error)}`);
	}

	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new Error(`Expected a JSON object in ${configPath}`);
	}

	const raw = parsed as Partial<Record<keyof LocalConfig, unknown>>;
	return {
		workerName:
			typeof raw.workerName === "string" && raw.workerName.trim().length > 0
				? raw.workerName.trim()
				: DEFAULT_LOCAL_CONFIG.workerName,
		d1DatabaseName:
			typeof raw.d1DatabaseName === "string" && raw.d1DatabaseName.trim().length > 0
				? raw.d1DatabaseName.trim()
				: DEFAULT_LOCAL_CONFIG.d1DatabaseName,
		routingMode: raw.routingMode === "ccf" ? "ccf" : DEFAULT_LOCAL_CONFIG.routingMode,
		ownerName:
			typeof raw.ownerName === "string" && raw.ownerName.trim().length > 0
				? raw.ownerName.trim()
				: DEFAULT_LOCAL_CONFIG.ownerName,
		ownerNameIpa:
			typeof raw.ownerNameIpa === "string" ? raw.ownerNameIpa.trim() : DEFAULT_LOCAL_CONFIG.ownerNameIpa,
		aiModel:
			raw.aiModel === "@cf/cloudflare/clef-flash" ? "@cf/cloudflare/clef-flash" : DEFAULT_LOCAL_CONFIG.aiModel,
		cfAccessTeamDomain:
			typeof raw.cfAccessTeamDomain === "string"
				? raw.cfAccessTeamDomain.trim()
				: DEFAULT_LOCAL_CONFIG.cfAccessTeamDomain,
	};
}

const config = loadLocalConfig();

/**
 * Infrastructure-as-code configuration for the You Shall Not Ring Worker.
 *
 * Why `cloudflare.config.ts`: The `cf` CLI binds Workers KV, Workers AI, Cloudflare D1,
 * non-secret config text, and encrypted runtime secrets in one type-checked file that
 * drives `.cloudflare/types/index.d.ts`.
 */
export default defineConfig({
	worker: {
		name: config.workerName,
		compatibilityDate: "2026-11-04",
		entrypoint,
		env: {
			// "all" handles *72 unconditional forwarding; "ccf" handles Contacts-Direct conditional forwarding.
			ROUTING_MODE: bindings.text(config.routingMode),
			OWNER_NAME: bindings.text(config.ownerName),
			OWNER_NAME_IPA: bindings.text(config.ownerNameIpa),
			AI_MODEL: bindings.text(config.aiModel), // Or "@cf/cloudflare/clef-flash" for ~39ms edge latency
			// Empty fails closed on /dashboard*; set in local.config.json (e.g. "your-team.cloudflareaccess.com")
			CF_ACCESS_TEAM_DOMAIN: bindings.text(config.cfAccessTeamDomain),
			ALLOWLIST_KV: bindings.kv(),
			CALL_LOGS_DB: bindings.d1({ name: config.d1DatabaseName }),
			AI: bindings.ai(),
			TWILIO_AUTH_TOKEN: bindings.secret(),
			SIP_ENDPOINT: bindings.secret(),
			ADMIN_TOKEN: bindings.secret(),
			CONTACT_HASH_SALT: bindings.secret(),
			CF_ACCESS_AUD: bindings.secret(),
		},
	},
});
