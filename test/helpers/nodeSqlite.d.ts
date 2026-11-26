declare module "node:sqlite" {
	export type SqliteInputValue = string | number | bigint | Uint8Array | null;

	export interface StatementSync {
		run(...params: SqliteInputValue[]): { changes: number | bigint; lastInsertRowid: number | bigint };
		get(...params: SqliteInputValue[]): Record<string, unknown> | undefined;
		all(...params: SqliteInputValue[]): Record<string, unknown>[];
	}

	export class DatabaseSync {
		constructor(path: string);
		exec(sql: string): void;
		prepare(sql: string): StatementSync;
		close(): void;
	}
}

declare module "node:fs" {
	export function existsSync(path: string): boolean;
	export function readFileSync(path: string, encoding: "utf8"): string;
}

declare module "node:path" {
	export function resolve(...paths: string[]): string;
}

declare const process: {
	cwd(): string;
};
