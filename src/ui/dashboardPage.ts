/**
 * Escapes untrusted text for safe insertion into HTML text nodes and attribute values.
 *
 * Why explicit escaping: The dashboard renders the authenticated Access identity email
 * and error messages directly in server-generated HTML without a templating library.
 *
 * @param value - Raw string to escape.
 * @returns HTML-escaped string.
 */
export function escapeHtml(value: string): string {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

/**
 * Renders the self-contained You Shall Not Ring call analytics and allowlist management dashboard.
 *
 * Why a single self-contained HTML document: Eliminates third-party CDN dependencies,
 * satisfies strict Content-Security-Policy (`default-src 'self'`), and renders all dynamic
 * API fields on the client strictly via `document.createElement` + `.textContent`.
 *
 * @param userEmail - Verified Cloudflare Access email address for the signed-in user.
 * @returns Complete HTML5 document string.
 */
export function renderDashboardHtml(userEmail: string): string {
	const safeEmail = escapeHtml(userEmail || "Authenticated User");

	return `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="color-scheme" content="light dark">
	<title>You Shall Not Ring — Call Screener &amp; Allowlist Dashboard</title>
	<style>
		:root {
			--bg-light: #f5f7fa;
			--bg-dark: #0e1116;
			--surface-light: #ffffff;
			--surface-dark: #161b22;
			--surface-subtle-light: #eef2f6;
			--surface-subtle-dark: #1f2630;
			--text-light: #111827;
			--text-dark: #f0f6fc;
			--muted-light: #4b5563;
			--muted-dark: #9ca3af;
			--border-light: #d1d9e4;
			--border-dark: #2d3643;
			--accent-light: #0f5bd8;
			--accent-dark: #6cb4ff;
			--accent-contrast-light: #ffffff;
			--accent-contrast-dark: #07192d;
			--success-light: #0d7a43;
			--success-dark: #4ade80;
			--success-bg-light: #dcfce7;
			--success-bg-dark: #0d3321;
			--danger-light: #b91c1c;
			--danger-dark: #f87171;
			--danger-bg-light: #fee2e2;
			--danger-bg-dark: #3b1419;
			--warn-light: #9a5b00;
			--warn-dark: #fbbf24;
			--warn-bg-light: #fef3c7;
			--warn-bg-dark: #38280d;
			--info-light: #0369a1;
			--info-dark: #38bdf8;
			--info-bg-light: #e0f2fe;
			--info-bg-dark: #0c2c40;
			--scrollbar-track-light: #e5e7eb;
			--scrollbar-track-dark: #1c2129;
			--scrollbar-thumb-light: #6b7280;
			--scrollbar-thumb-dark: #8b949e;

			--bg: var(--bg-light);
			--surface: var(--surface-light);
			--surface-subtle: var(--surface-subtle-light);
			--text: var(--text-light);
			--muted: var(--muted-light);
			--border: var(--border-light);
			--accent: var(--accent-light);
			--accent-contrast: var(--accent-contrast-light);
			--success: var(--success-light);
			--success-bg: var(--success-bg-light);
			--danger: var(--danger-light);
			--danger-bg: var(--danger-bg-light);
			--warn: var(--warn-light);
			--warn-bg: var(--warn-bg-light);
			--info: var(--info-light);
			--info-bg: var(--info-bg-light);
			--scrollbar-track: var(--scrollbar-track-light);
			--scrollbar-thumb: var(--scrollbar-thumb-light);

			color-scheme: light dark;
			scrollbar-color: var(--scrollbar-thumb) var(--scrollbar-track);
		}

		@media (prefers-color-scheme: dark) {
			:root {
				--bg: var(--bg-dark);
				--surface: var(--surface-dark);
				--surface-subtle: var(--surface-subtle-dark);
				--text: var(--text-dark);
				--muted: var(--muted-dark);
				--border: var(--border-dark);
				--accent: var(--accent-dark);
				--accent-contrast: var(--accent-contrast-dark);
				--success: var(--success-dark);
				--success-bg: var(--success-bg-dark);
				--danger: var(--danger-dark);
				--danger-bg: var(--danger-bg-dark);
				--warn: var(--warn-dark);
				--warn-bg: var(--warn-bg-dark);
				--info: var(--info-dark);
				--info-bg: var(--info-bg-dark);
				--scrollbar-track: var(--scrollbar-track-dark);
				--scrollbar-thumb: var(--scrollbar-thumb-dark);
			}
		}

		@supports (color: light-dark(white, black)) {
			:root {
				--bg: light-dark(var(--bg-light), var(--bg-dark));
				--surface: light-dark(var(--surface-light), var(--surface-dark));
				--surface-subtle: light-dark(var(--surface-subtle-light), var(--surface-subtle-dark));
				--text: light-dark(var(--text-light), var(--text-dark));
				--muted: light-dark(var(--muted-light), var(--muted-dark));
				--border: light-dark(var(--border-light), var(--border-dark));
				--accent: light-dark(var(--accent-light), var(--accent-dark));
				--accent-contrast: light-dark(var(--accent-contrast-light), var(--accent-contrast-dark));
				--success: light-dark(var(--success-light), var(--success-dark));
				--success-bg: light-dark(var(--success-bg-light), var(--success-bg-dark));
				--danger: light-dark(var(--danger-light), var(--danger-dark));
				--danger-bg: light-dark(var(--danger-bg-light), var(--danger-bg-dark));
				--warn: light-dark(var(--warn-light), var(--warn-dark));
				--warn-bg: light-dark(var(--warn-bg-light), var(--warn-bg-dark));
				--info: light-dark(var(--info-light), var(--info-dark));
				--info-bg: light-dark(var(--info-bg-light), var(--info-bg-dark));
				--scrollbar-track: light-dark(var(--scrollbar-track-light), var(--scrollbar-track-dark));
				--scrollbar-thumb: light-dark(var(--scrollbar-thumb-light), var(--scrollbar-thumb-dark));
			}
		}

		html {
			accent-color: var(--accent);
			font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
			line-height: 1.5;
		}

		*, *::before, *::after {
			box-sizing: border-box;
		}

		body {
			margin: 0;
			background: var(--bg);
			color: var(--text);
			min-block-size: 100vh;
		}

		:focus-visible {
			outline: 2px solid var(--accent);
			outline-offset: 2px;
		}

		.shell {
			max-inline-size: 1240px;
			margin-inline: auto;
			padding: 1.25rem 1.25rem 3rem;
		}

		.topbar {
			display: flex;
			flex-wrap: wrap;
			align-items: center;
			justify-content: space-between;
			gap: 1rem;
			padding-block-end: 1rem;
			margin-block-end: 1rem;
			border-block-end: 1px solid var(--border);
		}

		.brand-group {
			display: flex;
			align-items: center;
			gap: 0.75rem;
		}

		.brand-mark {
			display: inline-grid;
			place-items: center;
			inline-size: 2.35rem;
			block-size: 2.35rem;
			border-radius: 10px;
			background: var(--accent);
			color: var(--accent-contrast);
			font-weight: 800;
			font-size: 1.1rem;
			letter-spacing: -0.02em;
		}

		.brand-title {
			margin: 0;
			font-size: 1.35rem;
			line-height: 1.2;
		}

		.brand-subtitle {
			margin: 0;
			font-size: 0.85rem;
			color: var(--muted);
		}

		.topbar-controls {
			display: flex;
			flex-wrap: wrap;
			align-items: center;
			gap: 0.75rem;
		}

		.identity-badge {
			display: inline-flex;
			align-items: center;
			gap: 0.4rem;
			padding: 0.35rem 0.7rem;
			border-radius: 999px;
			border: 1px solid var(--border);
			background: var(--surface);
			font-size: 0.82rem;
			color: var(--muted);
		}

		.identity-dot {
			inline-size: 0.5rem;
			block-size: 0.5rem;
			border-radius: 50%;
			background: var(--success);
		}

		label.inline-label {
			display: inline-flex;
			align-items: center;
			gap: 0.45rem;
			font-size: 0.88rem;
			color: var(--muted);
			font-weight: 600;
		}

		select, input[type="search"], input[type="text"], input[type="tel"], textarea {
			font: inherit;
			color: var(--text);
			background: var(--surface);
			border: 1px solid var(--border);
			border-radius: 8px;
			padding: 0.45rem 0.7rem;
		}

		textarea {
			inline-size: 100%;
			resize: vertical;
			font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
			font-size: 0.85rem;
		}

		.btn {
			display: inline-flex;
			align-items: center;
			justify-content: center;
			gap: 0.35rem;
			font: inherit;
			font-size: 0.85rem;
			font-weight: 600;
			padding: 0.45rem 0.85rem;
			border-radius: 8px;
			border: 1px solid var(--border);
			background: var(--surface);
			color: var(--text);
			cursor: pointer;
			text-decoration: none;
			white-space: nowrap;
		}

		.btn:hover:not(:disabled) {
			background: var(--surface-subtle);
		}

		.btn:disabled {
			opacity: 0.55;
			cursor: not-allowed;
		}

		.btn-primary {
			background: var(--accent);
			border-color: var(--accent);
			color: var(--accent-contrast);
		}

		.btn-primary:hover:not(:disabled) {
			opacity: 0.92;
			background: var(--accent);
		}

		.btn-sm {
			padding: 0.28rem 0.55rem;
			font-size: 0.78rem;
		}

		.btn-allow {
			color: var(--success);
			border-color: var(--success);
		}

		.btn-block {
			color: var(--danger);
			border-color: var(--danger);
		}

		.status-banner {
			margin-block-end: 1rem;
			padding: 0.65rem 0.9rem;
			border-radius: 8px;
			border: 1px solid var(--border);
			background: var(--surface);
			font-size: 0.88rem;
		}

		.status-banner[hidden] {
			display: none;
		}

		.status-banner.error {
			background: var(--danger-bg);
			color: var(--danger);
			border-color: var(--danger);
		}

		.status-banner.success {
			background: var(--success-bg);
			color: var(--success);
			border-color: var(--success);
		}

		/* Tabs pattern: no padding/border/background on [role="tabpanel"] itself */
		.tablist {
			display: flex;
			flex-wrap: nowrap;
			overflow-x: auto;
			border-block-end: 1px solid var(--border);
			margin-block-end: 1rem;
		}

		[role="tab"] {
			position: relative;
			flex: none;
			background: transparent;
			border: 0;
			color: var(--muted);
			font: inherit;
			font-weight: 600;
			font-size: 0.95rem;
			padding: 0.75rem 1.15rem;
			cursor: pointer;
			white-space: nowrap;
		}

		[role="tab"][aria-selected="true"] {
			color: var(--accent);
		}

		[role="tab"][aria-selected="true"]::after {
			content: "";
			position: absolute;
			inset: auto 0 0;
			border-block-end: 3px solid var(--accent);
		}

		.panel-inner {
			display: grid;
			gap: 1.25rem;
		}

		.kpi-grid {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(195px, 1fr));
			gap: 0.85rem;
		}

		.card {
			background: var(--surface);
			border: 1px solid var(--border);
			border-radius: 12px;
			padding: 1rem 1.1rem;
		}

		.kpi-label {
			margin: 0;
			font-size: 0.8rem;
			font-weight: 600;
			color: var(--muted);
			text-transform: uppercase;
			letter-spacing: 0.04em;
		}

		.kpi-value {
			margin: 0.35rem 0 0.2rem;
			font-size: 1.7rem;
			font-weight: 700;
			line-height: 1.15;
		}

		.kpi-sub {
			margin: 0;
			font-size: 0.82rem;
			color: var(--muted);
		}

		.section-header {
			display: flex;
			flex-wrap: wrap;
			align-items: center;
			justify-content: space-between;
			gap: 0.75rem;
			margin-block-end: 0.75rem;
		}

		.section-title {
			margin: 0;
			font-size: 1rem;
		}

		.funnel-bar {
			display: flex;
			block-size: 14px;
			inline-size: 100%;
			border-radius: 999px;
			overflow: hidden;
			background: var(--surface-subtle);
			border: 1px solid var(--border);
		}

		.funnel-segment {
			block-size: 100%;
			min-inline-size: 0;
		}

		.seg-l1 { background: #dc2626; }
		.seg-l2 { background: #ea580c; }
		.seg-l3 { background: #d97706; }
		.seg-whisper { background: #7c3aed; }
		.seg-reached { background: #16a34a; }
		.seg-voicemail { background: #0284c7; }

		.funnel-legend {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
			gap: 0.5rem 0.9rem;
			margin-block-start: 0.85rem;
		}

		.legend-item {
			display: flex;
			align-items: center;
			justify-content: space-between;
			gap: 0.5rem;
			font-size: 0.84rem;
			padding: 0.35rem 0.55rem;
			border-radius: 8px;
			background: var(--surface-subtle);
		}

		.legend-label {
			display: inline-flex;
			align-items: center;
			gap: 0.45rem;
			color: var(--muted);
		}

		.legend-swatch {
			inline-size: 0.65rem;
			block-size: 0.65rem;
			border-radius: 3px;
			flex-shrink: 0;
		}

		.toolbar {
			display: flex;
			flex-wrap: wrap;
			align-items: center;
			justify-content: space-between;
			gap: 0.75rem;
		}

		.toolbar-filters {
			display: flex;
			flex-wrap: wrap;
			align-items: center;
			gap: 0.6rem;
			flex: 1;
		}

		.toolbar-filters input[type="search"] {
			min-inline-size: min(260px, 100%);
			flex: 1;
			max-inline-size: 380px;
		}

		.badge {
			display: inline-flex;
			align-items: center;
			padding: 0.15rem 0.5rem;
			border-radius: 999px;
			font-size: 0.75rem;
			font-weight: 600;
			background: var(--surface-subtle);
			color: var(--text);
			white-space: nowrap;
		}

		.badge-success { background: var(--success-bg); color: var(--success); }
		.badge-danger { background: var(--danger-bg); color: var(--danger); }
		.badge-warn { background: var(--warn-bg); color: var(--warn); }
		.badge-info { background: var(--info-bg); color: var(--info); }

		.subtext {
			display: block;
			font-size: 0.78rem;
			color: var(--muted);
			font-weight: 400;
			margin-block-start: 0.15rem;
		}

		.mono {
			font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
		}

		.cell-actions {
			display: flex;
			flex-wrap: wrap;
			gap: 0.35rem;
		}

		/* Responsive table pattern */
		.table-wrapper {
			overflow: auto;
			max-inline-size: 100%;
			max-block-size: min(560px, 75vh);
			container-type: inline-size;
			border: 1px solid var(--border);
			border-radius: 12px;
			background: var(--surface);
		}

		table {
			border-collapse: separate;
			border-spacing: 0;
			inline-size: 100%;
			font-size: 0.88rem;
		}

		thead {
			position: sticky;
			inset-block-start: 0;
			z-index: 1;
			background: var(--surface-subtle);
		}

		thead th {
			text-align: start;
			padding: 0.65rem 0.85rem;
			border-block-end: 1px solid var(--border);
			font-size: 0.76rem;
			text-transform: uppercase;
			letter-spacing: 0.04em;
			color: var(--muted);
			white-space: nowrap;
		}

		tbody th, tbody td {
			padding: 0.65rem 0.85rem;
			border-block-end: 1px solid var(--border);
			vertical-align: top;
		}

		tbody tr:last-child th,
		tbody tr:last-child td {
			border-block-end: 0;
		}

		tbody th {
			position: sticky;
			inset-inline-start: 0;
			z-index: 0;
			background: var(--surface);
			text-align: start;
			font-weight: 600;
			white-space: nowrap;
		}

		#calls-table {
			--label-2: "Time";
			--label-3: "Phase";
			--label-4: "Outcome";
			--label-5: "Duration & Cost";
			--label-6: "Actions";
		}

		#rules-table {
			--label-2: "Label";
			--label-3: "Status";
			--label-4: "Source";
			--label-5: "Expires";
			--label-6: "Actions";
		}

		@container (width < 680px) {
			table, thead, tbody, tr, th, td {
				display: block;
			}

			thead {
				display: none;
			}

			tbody {
				padding: 0.75rem;
			}

			tr {
				margin-block-end: 0.9rem;
				border: 1px solid var(--border);
				border-radius: 10px;
				background: var(--surface);
				overflow: hidden;
			}

			tr:last-child {
				margin-block-end: 0;
			}

			tbody th {
				position: sticky;
				inset-block-start: 0;
				z-index: 2;
				background: var(--surface-subtle);
				border-block-end: 1px solid var(--border);
			}

			tbody td {
				display: flex;
				justify-content: space-between;
				align-items: flex-start;
				gap: 0.75rem;
				text-align: end;
			}

			tbody td:last-child {
				border-block-end: 0;
			}

			td:nth-child(2)::before {
				content: var(--label-2) ": ";
				font-weight: 600;
				color: var(--muted);
				text-align: start;
				flex-shrink: 0;
			}

			td:nth-child(3)::before {
				content: var(--label-3) ": ";
				font-weight: 600;
				color: var(--muted);
				text-align: start;
				flex-shrink: 0;
			}

			td:nth-child(4)::before {
				content: var(--label-4) ": ";
				font-weight: 600;
				color: var(--muted);
				text-align: start;
				flex-shrink: 0;
			}

			td:nth-child(5)::before {
				content: var(--label-5) ": ";
				font-weight: 600;
				color: var(--muted);
				text-align: start;
				flex-shrink: 0;
			}

			td:nth-child(6)::before {
				content: var(--label-6) ": ";
				font-weight: 600;
				color: var(--muted);
				text-align: start;
				flex-shrink: 0;
			}

			.cell-actions {
				justify-content: flex-end;
			}

			.empty-row td {
				display: block;
				text-align: center;
			}

			.empty-row td::before {
				content: none;
			}
		}

		.pagination-bar {
			display: flex;
			flex-wrap: wrap;
			align-items: center;
			justify-content: space-between;
			gap: 0.75rem;
			font-size: 0.85rem;
			color: var(--muted);
		}

		.pagination-buttons {
			display: flex;
			gap: 0.5rem;
		}

		.manager-grid {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(310px, 1fr));
			gap: 1rem;
		}

		.form-stack {
			display: grid;
			gap: 0.75rem;
		}

		.field-row {
			display: grid;
			gap: 0.35rem;
		}

		.field-row label {
			font-size: 0.84rem;
			font-weight: 600;
			color: var(--muted);
		}

		.radio-group {
			display: flex;
			flex-wrap: wrap;
			gap: 1rem;
			font-size: 0.86rem;
		}

		.radio-option {
			display: inline-flex;
			align-items: center;
			gap: 0.4rem;
			cursor: pointer;
		}

		.hint-box {
			font-size: 0.8rem;
			color: var(--muted);
			background: var(--surface-subtle);
			padding: 0.5rem 0.75rem;
			border-radius: 8px;
		}

		.sync-meta-row {
			display: flex;
			flex-wrap: wrap;
			align-items: center;
			justify-content: space-between;
			gap: 0.75rem;
		}

		/* Native dialog pattern */
		dialog {
			max-inline-size: min(700px, 92vw);
			inline-size: 100%;
			max-block-size: 86vh;
			border: 1px solid var(--border);
			border-radius: 14px;
			padding: 0;
			background: var(--surface);
			color: var(--text);
			margin: auto;
			box-shadow: 0 24px 60px rgb(0 0 0 / 0.35);
		}

		dialog[open] {
			display: flex;
			flex-direction: column;
		}

		dialog:modal {
			overscroll-behavior: contain;
		}

		dialog::backdrop {
			overflow: hidden;
			overscroll-behavior: contain;
			background: rgb(0 0 0 / 0.55);
			backdrop-filter: blur(2px);
		}

		.dialog-header {
			display: flex;
			align-items: center;
			justify-content: space-between;
			gap: 1rem;
			padding: 1rem 1.25rem;
			border-block-end: 1px solid var(--border);
		}

		.dialog-header h1 {
			margin: 0;
			font-size: 1.15rem;
		}

		.dialog-body {
			padding: 1.1rem 1.25rem;
			overflow: auto;
			display: grid;
			gap: 0.9rem;
		}

		.detail-grid {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
			gap: 0.65rem;
		}

		.detail-item {
			padding: 0.6rem 0.75rem;
			border-radius: 8px;
			background: var(--surface-subtle);
		}

		.detail-term {
			font-size: 0.75rem;
			font-weight: 600;
			color: var(--muted);
			text-transform: uppercase;
			letter-spacing: 0.04em;
		}

		.detail-val {
			margin-block-start: 0.2rem;
			font-size: 0.9rem;
			word-break: break-word;
		}

		.transcript-box {
			padding: 0.8rem 0.9rem;
			border-radius: 8px;
			border: 1px solid var(--border);
			background: var(--bg);
			white-space: pre-wrap;
			word-break: break-word;
			font-size: 0.88rem;
			margin: 0;
		}

		.dialog-footer {
			display: flex;
			flex-wrap: wrap;
			align-items: center;
			justify-content: space-between;
			gap: 0.75rem;
			padding: 0.85rem 1.25rem;
			border-block-start: 1px solid var(--border);
		}
	</style>
</head>
<body>
	<div class="shell">
		<header class="topbar">
			<div class="brand-group">
				<div class="brand-mark" aria-hidden="true">Y</div>
				<div>
					<h1 class="brand-title">You Shall Not Ring</h1>
					<p class="brand-subtitle">Call Screener Analytics &amp; Allowlist Manager</p>
				</div>
			</div>
			<div class="topbar-controls">
				<span class="identity-badge" title="Signed in via Cloudflare Zero Trust Access">
					<span class="identity-dot" aria-hidden="true"></span>
					<span>${safeEmail}</span>
				</span>
				<label class="inline-label" for="period-select">
					<span>Period</span>
					<select id="period-select" name="period">
						<option value="7d">Last 7 days</option>
						<option value="30d" selected>Last 30 days</option>
						<option value="month">This month</option>
						<option value="all">All time</option>
					</select>
				</label>
			</div>
		</header>

		<div id="status-banner" class="status-banner" role="status" aria-live="polite" hidden></div>

		<div class="tabs">
			<div focusgroup="tablist nomemory" aria-label="Dashboard sections" class="tablist">
				<button type="button" role="tab" id="tab-overview" aria-selected="true" focusgroupstart>Call Effectiveness &amp; Spend</button>
				<button type="button" role="tab" id="tab-allowlist" aria-selected="false">Allowlist &amp; CSV Manager</button>
			</div>

			<div role="tabpanel" id="panel-overview" aria-labelledby="tab-overview" tabindex="0">
				<div class="panel-inner">
					<section aria-label="Key metrics" class="kpi-grid">
						<article class="card">
							<p class="kpi-label">Total Calls</p>
							<p id="kpi-total-calls" class="kpi-value">—</p>
							<p id="kpi-total-sub" class="kpi-sub">Loading…</p>
						</article>
						<article class="card">
							<p class="kpi-label">Spam Stopped</p>
							<p id="kpi-spam-stopped" class="kpi-value">—</p>
							<p id="kpi-spam-sub" class="kpi-sub">—</p>
						</article>
						<article class="card">
							<p class="kpi-label">Keypad Drops (L2)</p>
							<p id="kpi-l2-drops" class="kpi-value">—</p>
							<p id="kpi-l2-sub" class="kpi-sub">—</p>
						</article>
						<article class="card">
							<p class="kpi-label">Clef AI Drops (L3)</p>
							<p id="kpi-l3-drops" class="kpi-value">—</p>
							<p id="kpi-l3-sub" class="kpi-sub">—</p>
						</article>
						<article class="card">
							<p class="kpi-label">Est. Twilio Spend</p>
							<p id="kpi-spend" class="kpi-value">—</p>
							<p id="kpi-spend-sub" class="kpi-sub">Usage vs $1.15/mo base</p>
						</article>
					</section>

					<section class="card" aria-labelledby="funnel-heading">
						<div class="section-header">
							<h2 id="funnel-heading" class="section-title">Call Screening Phase Funnel</h2>
							<span id="funnel-total-note" class="brand-subtitle"></span>
						</div>
						<div id="funnel-bar" class="funnel-bar" aria-hidden="true"></div>
						<div id="funnel-legend" class="funnel-legend"></div>
					</section>

					<section aria-labelledby="calls-table-heading">
						<div class="section-header">
							<h2 id="calls-table-heading" class="section-title">Recent Screened Calls</h2>
						</div>
						<div class="toolbar">
							<div class="toolbar-filters">
								<select id="calls-filter-select" aria-label="Filter calls by outcome or phase">
									<option value="">All outcomes &amp; phases</option>
									<optgroup label="By Outcome">
										<option value="outcome:BLOCKED_L1">Blocked (L1)</option>
										<option value="outcome:STOPPED_L2_DTMF_WRONG">Wrong Digit (L2)</option>
										<option value="outcome:STOPPED_L2_DTMF_ABANDONED">Abandoned Keypad (L2)</option>
										<option value="outcome:STOPPED_L3_SILENCE">Silent Hangup (L3)</option>
										<option value="outcome:STOPPED_L3_AI_SPAM">Clef AI Spam (L3)</option>
										<option value="outcome:REJECTED_UNCERTAIN_BLOCKED">Whisper Blocked</option>
										<option value="outcome:REJECTED_UNCERTAIN_DISMISSED">Whisper Dismissed</option>
										<option value="outcome:CONNECTED_ALLOWLIST">Connected (Allowlist)</option>
										<option value="outcome:CONNECTED_AI_ALLOW">Connected (AI Allow)</option>
										<option value="outcome:CONNECTED_UNCERTAIN_ACCEPTED">Connected (Whisper Accepted)</option>
										<option value="outcome:MISSED_VOICEMAIL">Voicemail</option>
										<option value="outcome:IN_PROGRESS">In Progress</option>
									</optgroup>
									<optgroup label="By Furthest Phase">
										<option value="phase:L1_ALLOWLIST">L1 Allowlist</option>
										<option value="phase:L2_DTMF">L2 Keypad</option>
										<option value="phase:L3_SPEECH">L3 Speech</option>
										<option value="phase:L3_CLEF">L3 Clef AI</option>
										<option value="phase:WHISPER">Whisper</option>
										<option value="phase:BRIDGED">Bridged</option>
										<option value="phase:VOICEMAIL">Voicemail</option>
									</optgroup>
								</select>
								<input type="search" id="calls-search-input" placeholder="Search phone, label, transcript, or reason…" aria-label="Search call logs">
							</div>
							<button type="button" id="calls-refresh-btn" class="btn">Refresh</button>
						</div>

						<div tabindex="0" role="region" aria-labelledby="calls-table-heading" class="table-wrapper" style="margin-block-start: 0.75rem;">
							<table id="calls-table">
								<thead>
									<tr>
										<th scope="col">Caller</th>
										<th scope="col">Time</th>
										<th scope="col">Phase</th>
										<th scope="col">Outcome</th>
										<th scope="col">Duration &amp; Cost</th>
										<th scope="col">Actions</th>
									</tr>
								</thead>
								<tbody id="calls-tbody">
									<tr class="empty-row"><td colspan="6">Loading call logs…</td></tr>
								</tbody>
							</table>
						</div>

						<div class="pagination-bar" style="margin-block-start: 0.65rem;">
							<span id="calls-page-info">Showing 0 calls</span>
							<div class="pagination-buttons">
								<button type="button" id="calls-prev-btn" class="btn btn-sm" disabled>Previous</button>
								<button type="button" id="calls-next-btn" class="btn btn-sm" disabled>Next</button>
							</div>
						</div>
					</section>
				</div>
			</div>

			<div role="tabpanel" id="panel-allowlist" aria-labelledby="tab-allowlist" hidden="until-found">
				<div class="panel-inner">
					<section class="card" aria-labelledby="contacts-sync-heading">
						<div class="sync-meta-row">
							<div>
								<h2 id="contacts-sync-heading" class="section-title">iOS Shortcut Contacts Sync (Hashed KV Snapshot)</h2>
								<p class="brand-subtitle">Phone numbers from your device Contacts are stored as salted 128-bit HMAC hashes in Workers KV.</p>
							</div>
							<div style="text-align: end;">
								<strong id="contacts-sync-count">—</strong>
								<span id="contacts-sync-updated" class="subtext">Last synced: —</span>
							</div>
						</div>
					</section>

					<div class="manager-grid">
						<section class="card" aria-labelledby="csv-importer-heading">
							<h2 id="csv-importer-heading" class="section-title" style="margin-block-end: 0.65rem;">CSV Upload / Paste Importer</h2>
							<form id="csv-import-form" class="form-stack">
								<div class="field-row">
									<label for="csv-file-input">Upload CSV or Contacts file</label>
									<input type="file" id="csv-file-input" accept=".csv,text/csv,text/plain">
								</div>
								<div class="field-row">
									<label for="csv-textarea">Or paste CSV rows</label>
									<textarea id="csv-textarea" rows="5" placeholder="+14155550199,Mom&#10;(415) 555-0142,Doctor Office"></textarea>
								</div>
								<div class="hint-box">
									Format hint: <code class="mono">phone,label</code> (header optional; Google/Apple Contacts CSV columns like <code class="mono">First Name</code>, <code class="mono">Last Name</code>, <code class="mono">Phone</code> are also detected).
								</div>
								<div class="radio-group" role="radiogroup" aria-label="CSV import mode">
									<label class="radio-option">
										<input type="radio" name="csv-mode" value="merge" checked>
										<span>Merge with existing rules</span>
									</label>
									<label class="radio-option">
										<input type="radio" name="csv-mode" value="replace_csv">
										<span>Replace CSV imports</span>
									</label>
								</div>
								<div>
									<button type="submit" id="csv-import-btn" class="btn btn-primary">Import CSV</button>
								</div>
							</form>
						</section>

						<section class="card" aria-labelledby="add-rule-heading">
							<h2 id="add-rule-heading" class="section-title" style="margin-block-end: 0.65rem;">Add Number Form</h2>
							<form id="add-rule-form" class="form-stack">
								<div class="field-row">
									<label for="rule-phone-input">Phone Number (E.164 or 10-digit US)</label>
									<input type="tel" id="rule-phone-input" required placeholder="+14155550199 or (415) 555-0199">
								</div>
								<div class="field-row">
									<label for="rule-label-input">Label (optional)</label>
									<input type="text" id="rule-label-input" maxlength="120" placeholder="e.g. Pediatrician, Alex">
								</div>
								<div class="field-row">
									<label for="rule-status-select">Disposition</label>
									<select id="rule-status-select">
										<option value="allowed" selected>Allowed (Bypass Screening)</option>
										<option value="blocked">Blocked (Hangup Immediately)</option>
									</select>
								</div>
								<div class="hint-box">
									Manual rules are saved permanently in both D1 and Workers KV until edited or deleted.
								</div>
								<div>
									<button type="submit" id="add-rule-btn" class="btn btn-primary">Save Rule</button>
								</div>
							</form>
						</section>
					</div>

					<section aria-labelledby="rules-table-heading">
						<div class="section-header">
							<h2 id="rules-table-heading" class="section-title">Active Caller Rules</h2>
						</div>
						<div class="toolbar">
							<div class="toolbar-filters">
								<select id="rules-status-filter" aria-label="Filter rules by status">
									<option value="">All statuses</option>
									<option value="allowed">Allowed</option>
									<option value="blocked">Blocked</option>
								</select>
								<input type="search" id="rules-search-input" placeholder="Search number or label…" aria-label="Search allowlist rules">
							</div>
							<a href="/dashboard/api/allowlist/export.csv" download="you-shall-not-ring-allowlist.csv" class="btn">Export CSV</a>
						</div>

						<div tabindex="0" role="region" aria-labelledby="rules-table-heading" class="table-wrapper" style="margin-block-start: 0.75rem;">
							<table id="rules-table">
								<thead>
									<tr>
										<th scope="col">Number</th>
										<th scope="col">Label</th>
										<th scope="col">Status</th>
										<th scope="col">Source</th>
										<th scope="col">Expires</th>
										<th scope="col">Actions</th>
									</tr>
								</thead>
								<tbody id="rules-tbody">
									<tr class="empty-row"><td colspan="6">Loading rules…</td></tr>
								</tbody>
							</table>
						</div>
					</section>
				</div>
			</div>
		</div>
	</div>

	<dialog id="call-detail-dialog" closedby="any" aria-labelledby="call-detail-title">
		<div class="dialog-header">
			<h1 id="call-detail-title">Call Details</h1>
			<form method="dialog">
				<button type="submit" class="btn btn-sm" autofocus>Close</button>
			</form>
		</div>
		<div id="call-detail-body" class="dialog-body"></div>
		<div class="dialog-footer">
			<div id="call-detail-actions" class="cell-actions"></div>
			<form method="dialog">
				<button type="submit" class="btn">Close</button>
			</form>
		</div>
	</dialog>

	<script>
		(() => {
			const PAGE_SIZE = 50;
			const state = {
				period: "30d",
				callsOffset: 0,
				callsTotal: 0,
				callsFilter: "",
				callsSearch: "",
				rulesStatus: "",
				rulesSearch: "",
			};

			const bannerEl = document.getElementById("status-banner");
			const periodSelect = document.getElementById("period-select");
			const tabButtons = Array.from(document.querySelectorAll('[role="tab"]'));
			const tabPanels = Array.from(document.querySelectorAll('[role="tabpanel"]'));

			const callsFilterSelect = document.getElementById("calls-filter-select");
			const callsSearchInput = document.getElementById("calls-search-input");
			const callsRefreshBtn = document.getElementById("calls-refresh-btn");
			const callsTbody = document.getElementById("calls-tbody");
			const callsPageInfo = document.getElementById("calls-page-info");
			const callsPrevBtn = document.getElementById("calls-prev-btn");
			const callsNextBtn = document.getElementById("calls-next-btn");

			const rulesStatusFilter = document.getElementById("rules-status-filter");
			const rulesSearchInput = document.getElementById("rules-search-input");
			const rulesTbody = document.getElementById("rules-tbody");

			const csvImportForm = document.getElementById("csv-import-form");
			const csvFileInput = document.getElementById("csv-file-input");
			const csvTextarea = document.getElementById("csv-textarea");
			const addRuleForm = document.getElementById("add-rule-form");
			const rulePhoneInput = document.getElementById("rule-phone-input");
			const ruleLabelInput = document.getElementById("rule-label-input");
			const ruleStatusSelect = document.getElementById("rule-status-select");

			const dialog = document.getElementById("call-detail-dialog");
			const dialogBody = document.getElementById("call-detail-body");
			const dialogActions = document.getElementById("call-detail-actions");

			function el(tag, className, text) {
				const node = document.createElement(tag);
				if (className) {
					node.className = className;
				}
				if (text !== undefined && text !== null) {
					node.textContent = String(text);
				}
				return node;
			}

			function showBanner(message, kind) {
				bannerEl.textContent = message;
				bannerEl.className = "status-banner " + (kind === "error" ? "error" : "success");
				bannerEl.hidden = false;
			}

			function clearBanner() {
				bannerEl.hidden = true;
				bannerEl.textContent = "";
			}

			function formatCurrencyFromCents(cents) {
				const numeric = Number(cents);
				if (!Number.isFinite(numeric)) {
					return "$0.00";
				}
				return "$" + (numeric / 100).toFixed(2);
			}

			function formatDateTime(iso) {
				if (!iso) {
					return "—";
				}
				const date = new Date(iso);
				if (Number.isNaN(date.getTime())) {
					return String(iso);
				}
				return date.toLocaleString(undefined, {
					month: "short",
					day: "numeric",
					hour: "numeric",
					minute: "2-digit",
				});
			}

			function isDialablePhone(value) {
				return typeof value === "string" && /^\\+?[1-9]\\d{6,14}$/.test(value.trim());
			}

			async function apiFetch(url, options) {
				const response = await fetch(url, options);
				let payload = null;
				try {
					payload = await response.json();
				} catch (err) {
					if (!response.ok) {
						throw new Error("Request failed (" + response.status + ")");
					}
					throw err;
				}
				if (!response.ok) {
					const msg = payload && typeof payload.error === "string"
						? payload.error
						: "Request failed (" + response.status + ")";
					throw new Error(msg);
				}
				return payload;
			}

			/* Tabs selection + beforematch + focusgroup fallback */
			function selectTab(selectedTab, shouldFocus) {
				for (const tab of tabButtons) {
					const isSelected = tab === selectedTab;
					tab.setAttribute("aria-selected", isSelected ? "true" : "false");
					tab.toggleAttribute("focusgroupstart", isSelected);
				}
				for (const panel of tabPanels) {
					const matches = panel.getAttribute("aria-labelledby") === selectedTab.id;
					if (matches) {
						panel.removeAttribute("hidden");
						panel.setAttribute("tabindex", "0");
					} else {
						panel.setAttribute("hidden", "until-found");
						panel.removeAttribute("tabindex");
					}
				}
				if (shouldFocus) {
					selectedTab.focus();
				}
				selectedTab.scrollIntoView({ block: "nearest", inline: "nearest" });
			}

			for (const tab of tabButtons) {
				tab.addEventListener("click", () => selectTab(tab, false));
				tab.addEventListener("focus", () => selectTab(tab, false));
			}

			for (const panel of tabPanels) {
				panel.addEventListener("beforematch", () => {
					const matchingId = panel.getAttribute("aria-labelledby");
					const matchingTab = tabButtons.find((t) => t.id === matchingId);
					if (matchingTab) {
						selectTab(matchingTab, false);
					}
				});
			}

			if (!Object.hasOwn(HTMLElement.prototype, "focusGroup")) {
				const tablist = document.querySelector('[focusgroup~="tablist"]');
				if (tablist) {
					tablist.addEventListener("keydown", (event) => {
						const idx = tabButtons.indexOf(document.activeElement);
						if (idx === -1) {
							return;
						}
						let nextIdx = -1;
						if (event.key === "ArrowRight") {
							nextIdx = (idx + 1) % tabButtons.length;
						} else if (event.key === "ArrowLeft") {
							nextIdx = (idx - 1 + tabButtons.length) % tabButtons.length;
						} else if (event.key === "Home") {
							nextIdx = 0;
						} else if (event.key === "End") {
							nextIdx = tabButtons.length - 1;
						}
						if (nextIdx !== -1) {
							event.preventDefault();
							selectTab(tabButtons[nextIdx], true);
						}
					});
				}
			}

			/* Dialog close reset + Safari closedby fallback */
			dialog.addEventListener("close", () => {
				dialog.returnValue = "";
			});

			if (!("closedBy" in HTMLDialogElement.prototype)) {
				const outside = (e, dlg) => {
					const r = dlg.getBoundingClientRect();
					return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
				};
				for (const dlg of document.querySelectorAll('dialog[closedby="any"]')) {
					let pressedOutside = false;
					dlg.addEventListener("pointerdown", (e) => {
						pressedOutside = outside(e, dlg);
					});
					dlg.addEventListener("pointerup", (e) => {
						if (pressedOutside && outside(e, dlg)) {
							dlg.close();
						}
						pressedOutside = false;
					});
				}
			}

			function renderSummary(summary, contactsSync) {
				document.getElementById("kpi-total-calls").textContent = String(summary.totalCalls);
				document.getElementById("kpi-total-sub").textContent =
					summary.reachedUserCount + " reached you · " + summary.voicemailCount + " voicemail";

				document.getElementById("kpi-spam-stopped").textContent =
					summary.spamStoppedCount + " (" + summary.spamStoppedPct + "%)";
				document.getElementById("kpi-spam-sub").textContent =
					summary.stoppedAtL1Blocked + " L1 · " + summary.rejectedAtWhisper + " whisper rejected";

				const l2Total = summary.stoppedAtL2Wrong + summary.stoppedAtL2Abandoned;
				document.getElementById("kpi-l2-drops").textContent = String(l2Total);
				document.getElementById("kpi-l2-sub").textContent =
					summary.stoppedAtL2Wrong + " wrong digit · " + summary.stoppedAtL2Abandoned + " abandoned";

				const l3Total = summary.stoppedAtL3Silence + summary.stoppedAtL3AiSpam;
				document.getElementById("kpi-l3-drops").textContent = String(l3Total);
				document.getElementById("kpi-l3-sub").textContent =
					summary.stoppedAtL3AiSpam + " AI spam · " + summary.stoppedAtL3Silence + " silent";

				document.getElementById("kpi-spend").textContent = formatCurrencyFromCents(summary.totalEstimatedCostCents);
				const baseText = summary.fixedNumberCostCents === 27 ? "$0.27/7d base" : "$1.15/mo base";
				document.getElementById("kpi-spend-sub").textContent =
					"Usage " + formatCurrencyFromCents(summary.usageCostCents) + " + " + baseText;

				const funnelSegments = [
					{ label: "L1 Blocked", count: summary.stoppedAtL1Blocked, cls: "seg-l1" },
					{ label: "L2 Wrong/Abandoned", count: l2Total, cls: "seg-l2" },
					{ label: "L3 Silence/AI Spam", count: l3Total, cls: "seg-l3" },
					{ label: "Whisper Rejected", count: summary.rejectedAtWhisper, cls: "seg-whisper" },
					{ label: "Reached You", count: summary.reachedUserCount, cls: "seg-reached" },
					{ label: "Voicemail", count: summary.voicemailCount, cls: "seg-voicemail" },
				];

				const funnelTotal = funnelSegments.reduce((acc, s) => acc + s.count, 0);
				document.getElementById("funnel-total-note").textContent =
					summary.inProgressCount > 0 ? summary.inProgressCount + " in progress" : "";

				const barEl = document.getElementById("funnel-bar");
				const legendEl = document.getElementById("funnel-legend");
				barEl.replaceChildren();
				legendEl.replaceChildren();

				for (const seg of funnelSegments) {
					if (funnelTotal > 0 && seg.count > 0) {
						const pct = (seg.count / funnelTotal) * 100;
						const segDiv = el("div", "funnel-segment " + seg.cls);
						segDiv.style.width = pct.toFixed(2) + "%";
						segDiv.title = seg.label + ": " + seg.count;
						barEl.appendChild(segDiv);
					}

					const item = el("div", "legend-item");
					const left = el("span", "legend-label");
					left.appendChild(el("span", "legend-swatch " + seg.cls));
					left.appendChild(el("span", "", seg.label));
					item.appendChild(left);
					item.appendChild(el("strong", "", String(seg.count)));
					legendEl.appendChild(item);
				}

				renderContactsSync(contactsSync);
			}

			function renderContactsSync(contactsSync) {
				const countEl = document.getElementById("contacts-sync-count");
				const updatedEl = document.getElementById("contacts-sync-updated");
				if (!contactsSync) {
					countEl.textContent = "0 synced";
					updatedEl.textContent = "Last synced: Never";
					return;
				}
				countEl.textContent = contactsSync.count + " synced contacts";
				updatedEl.textContent = "Last synced: " + (contactsSync.updatedAt ? formatDateTime(contactsSync.updatedAt) : "Never");
			}

			function outcomeBadgeClass(outcome) {
				if (outcome.startsWith("CONNECTED_")) {
					return "badge badge-success";
				}
				if (outcome === "MISSED_VOICEMAIL") {
					return "badge badge-info";
				}
				if (outcome === "IN_PROGRESS") {
					return "badge badge-warn";
				}
				return "badge badge-danger";
			}

			function openCallDetail(call) {
				document.getElementById("call-detail-title").textContent =
					"Call from " + (call.callerLabel ? call.callerLabel + " (" + call.from_number + ")" : call.from_number);

				dialogBody.replaceChildren();

				const grid = el("div", "detail-grid");
				const fields = [
					["Call SID", call.call_sid],
					["Caller Number", call.from_number],
					["Caller Label", call.callerLabel || "—"],
					["Layer 1 Trust", call.caller_trust],
					["Started", formatDateTime(call.started_at)],
					["Ended", formatDateTime(call.ended_at)],
					["Furthest Phase", call.furthest_phase],
					["Final Outcome", call.final_outcome],
					["Expected / Pressed Digit", (call.expected_digit || "—") + " / " + (call.pressed_digit || "—")],
					["Speech Attempts", String(call.speech_attempts)],
					["Clef Decision", call.ai_decision || "—"],
					["Clef Category", call.ai_category || "—"],
					["Clef Confidence", call.ai_confidence !== null && call.ai_confidence !== undefined ? String(call.ai_confidence) : "—"],
					["Injection Score", call.prompt_injection_score !== null && call.prompt_injection_score !== undefined ? String(call.prompt_injection_score) : "—"],
					["Inbound Duration", call.inbound_duration_sec + "s"],
					["SIP Bridge Duration", call.sip_duration_sec + "s"],
					["Estimated Cost", formatCurrencyFromCents(call.estimated_cost_cents)],
				];

				for (const [label, value] of fields) {
					const card = el("div", "detail-item");
					card.appendChild(el("div", "detail-term", label));
					card.appendChild(el("div", "detail-val", value));
					grid.appendChild(card);
				}
				dialogBody.appendChild(grid);

				const reasonWrap = el("div");
				reasonWrap.appendChild(el("div", "detail-term", "Outcome Reason"));
				reasonWrap.appendChild(el("p", "transcript-box", call.outcome_reason || "—"));
				dialogBody.appendChild(reasonWrap);

				const transcriptWrap = el("div");
				transcriptWrap.appendChild(el("div", "detail-term", "Speech Transcript"));
				transcriptWrap.appendChild(el("pre", "transcript-box", call.transcript || "(No transcript captured)"));
				dialogBody.appendChild(transcriptWrap);

				dialogActions.replaceChildren();
				if (isDialablePhone(call.from_number)) {
					const allowBtn = el("button", "btn btn-sm btn-allow", "Allow Number");
					allowBtn.type = "button";
					allowBtn.addEventListener("click", async () => {
						await mutateRule(call.from_number, "allowed", true);
						dialog.close();
					});
					const blockBtn = el("button", "btn btn-sm btn-block", "Block Number");
					blockBtn.type = "button";
					blockBtn.addEventListener("click", async () => {
						await mutateRule(call.from_number, "blocked", true);
						dialog.close();
					});
					dialogActions.appendChild(allowBtn);
					dialogActions.appendChild(blockBtn);
				}

				dialog.showModal();
			}

			function renderCallsTable(data) {
				state.callsTotal = data.total || 0;
				callsTbody.replaceChildren();

				if (!data.items || data.items.length === 0) {
					const tr = el("tr", "empty-row");
					const td = el("td", "", "No calls matched the current filters.");
					td.colSpan = 6;
					tr.appendChild(td);
					callsTbody.appendChild(tr);
				} else {
					for (const call of data.items) {
						const tr = el("tr");

						const callerTh = el("th");
						callerTh.scope = "row";
						callerTh.appendChild(el("span", "mono", call.from_number));
						const callerMeta = call.callerLabel
							? call.callerLabel + " · " + call.caller_trust
							: "trust: " + call.caller_trust;
						callerTh.appendChild(el("span", "subtext", callerMeta));
						tr.appendChild(callerTh);

						const timeTd = el("td", "", formatDateTime(call.started_at));
						tr.appendChild(timeTd);

						const phaseTd = el("td");
						phaseTd.appendChild(el("span", "badge", call.furthest_phase));
						tr.appendChild(phaseTd);

						const outcomeTd = el("td");
						outcomeTd.appendChild(el("span", outcomeBadgeClass(call.final_outcome), call.final_outcome));
						const outcomeSub = call.ai_category
							? call.ai_category + (call.outcome_reason ? " — " + call.outcome_reason : "")
							: (call.outcome_reason || "");
						if (outcomeSub) {
							outcomeTd.appendChild(el("span", "subtext", outcomeSub));
						}
						tr.appendChild(outcomeTd);

						const costTd = el("td");
						costTd.appendChild(el("span", "", formatCurrencyFromCents(call.estimated_cost_cents)));
						costTd.appendChild(el("span", "subtext", call.inbound_duration_sec + "s in / " + call.sip_duration_sec + "s sip"));
						tr.appendChild(costTd);

						const actionsTd = el("td");
						const actionsWrap = el("div", "cell-actions");

						const inspectBtn = el("button", "btn btn-sm", "Inspect");
						inspectBtn.type = "button";
						inspectBtn.addEventListener("click", () => openCallDetail(call));
						actionsWrap.appendChild(inspectBtn);

						if (isDialablePhone(call.from_number)) {
							const allowBtn = el("button", "btn btn-sm btn-allow", "Allow");
							allowBtn.type = "button";
							allowBtn.addEventListener("click", () => mutateRule(call.from_number, "allowed", true));
							actionsWrap.appendChild(allowBtn);

							const blockBtn = el("button", "btn btn-sm btn-block", "Block");
							blockBtn.type = "button";
							blockBtn.addEventListener("click", () => mutateRule(call.from_number, "blocked", true));
							actionsWrap.appendChild(blockBtn);
						}

						actionsTd.appendChild(actionsWrap);
						tr.appendChild(actionsTd);
						callsTbody.appendChild(tr);
					}
				}

				const start = state.callsTotal === 0 ? 0 : state.callsOffset + 1;
				const end = Math.min(state.callsTotal, state.callsOffset + (data.items ? data.items.length : 0));
				callsPageInfo.textContent = "Showing " + start + "–" + end + " of " + state.callsTotal + " calls";
				callsPrevBtn.disabled = state.callsOffset <= 0;
				callsNextBtn.disabled = state.callsOffset + PAGE_SIZE >= state.callsTotal;
			}

			function renderRulesTable(rules) {
				rulesTbody.replaceChildren();

				if (!rules || rules.length === 0) {
					const tr = el("tr", "empty-row");
					const td = el("td", "", "No active allowlist or blocklist rules found.");
					td.colSpan = 6;
					tr.appendChild(td);
					rulesTbody.appendChild(tr);
					return;
				}

				for (const rule of rules) {
					const tr = el("tr");

					const phoneTh = el("th");
					phoneTh.scope = "row";
					phoneTh.appendChild(el("span", "mono", rule.phone_e164));
					if (rule.reason) {
						phoneTh.appendChild(el("span", "subtext", rule.reason));
					}
					tr.appendChild(phoneTh);

					tr.appendChild(el("td", "", rule.label || "—"));

					const statusTd = el("td");
					const statusBadge = el(
						"span",
						rule.status === "allowed" ? "badge badge-success" : "badge badge-danger",
						rule.status,
					);
					statusTd.appendChild(statusBadge);
					tr.appendChild(statusTd);

					const sourceTd = el("td");
					sourceTd.appendChild(el("span", "badge", rule.source));
					tr.appendChild(sourceTd);

					const expiresTd = el(
						"td",
						"",
						rule.expires_at ? formatDateTime(rule.expires_at) : "Permanent",
					);
					tr.appendChild(expiresTd);

					const actionsTd = el("td");
					const actionsWrap = el("div", "cell-actions");

					if (rule.expires_at) {
						const permBtn = el("button", "btn btn-sm", "Make Permanent");
						permBtn.type = "button";
						permBtn.addEventListener("click", () =>
							mutateRule(rule.phone_e164, rule.status, true, rule.label || undefined, "Promoted to permanent"),
						);
						actionsWrap.appendChild(permBtn);
					}

					const nextStatus = rule.status === "allowed" ? "blocked" : "allowed";
					const toggleBtn = el(
						"button",
						"btn btn-sm " + (nextStatus === "allowed" ? "btn-allow" : "btn-block"),
						nextStatus === "allowed" ? "Allow" : "Block",
					);
					toggleBtn.type = "button";
					toggleBtn.addEventListener("click", () =>
						mutateRule(rule.phone_e164, nextStatus, true, rule.label || undefined, "Toggled from dashboard"),
					);
					actionsWrap.appendChild(toggleBtn);

					const deleteBtn = el("button", "btn btn-sm", "Delete");
					deleteBtn.type = "button";
					deleteBtn.addEventListener("click", () => removeRule(rule.phone_e164));
					actionsWrap.appendChild(deleteBtn);

					actionsTd.appendChild(actionsWrap);
					tr.appendChild(actionsTd);
					rulesTbody.appendChild(tr);
				}
			}

			async function loadSummary() {
				const data = await apiFetch("/dashboard/api/summary?period=" + encodeURIComponent(state.period));
				renderSummary(data.summary, data.contactsSync);
			}

			async function loadCalls() {
				const params = new URLSearchParams();
				params.set("period", state.period);
				params.set("limit", String(PAGE_SIZE));
				params.set("offset", String(state.callsOffset));
				if (state.callsFilter.startsWith("outcome:")) {
					params.set("outcome", state.callsFilter.slice("outcome:".length));
				} else if (state.callsFilter.startsWith("phase:")) {
					params.set("phase", state.callsFilter.slice("phase:".length));
				}
				if (state.callsSearch.trim()) {
					params.set("search", state.callsSearch.trim());
				}
				const data = await apiFetch("/dashboard/api/calls?" + params.toString());
				renderCallsTable(data);
			}

			async function loadAllowlist() {
				const params = new URLSearchParams();
				if (state.rulesStatus) {
					params.set("status", state.rulesStatus);
				}
				if (state.rulesSearch.trim()) {
					params.set("search", state.rulesSearch.trim());
				}
				const query = params.toString();
				const data = await apiFetch("/dashboard/api/allowlist" + (query ? "?" + query : ""));
				renderContactsSync(data.contactsSync);
				renderRulesTable(data.rules);
			}

			async function refreshAll() {
				clearBanner();
				try {
					await Promise.all([loadSummary(), loadCalls(), loadAllowlist()]);
				} catch (err) {
					showBanner(err instanceof Error ? err.message : "Failed to load dashboard data", "error");
				}
			}

			async function mutateRule(phone, status, permanent, label, reason) {
				clearBanner();
				try {
					await apiFetch("/dashboard/api/allowlist", {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({
							phone,
							status,
							permanent,
							...(label ? { label } : {}),
							...(reason ? { reason } : {}),
						}),
					});
					showBanner("Saved rule for " + phone + " (" + status + ").", "success");
					await Promise.all([loadAllowlist(), loadCalls(), loadSummary()]);
				} catch (err) {
					showBanner(err instanceof Error ? err.message : "Failed to save rule", "error");
				}
			}

			async function removeRule(phone) {
				clearBanner();
				try {
					await apiFetch("/dashboard/api/allowlist", {
						method: "DELETE",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({ phone }),
					});
					showBanner("Deleted rule for " + phone + ".", "success");
					await Promise.all([loadAllowlist(), loadCalls(), loadSummary()]);
				} catch (err) {
					showBanner(err instanceof Error ? err.message : "Failed to delete rule", "error");
				}
			}

			periodSelect.addEventListener("change", () => {
				state.period = periodSelect.value;
				state.callsOffset = 0;
				refreshAll();
			});

			callsFilterSelect.addEventListener("change", () => {
				state.callsFilter = callsFilterSelect.value;
				state.callsOffset = 0;
				loadCalls().catch((err) => showBanner(err.message, "error"));
			});

			let callsSearchTimer = null;
			callsSearchInput.addEventListener("input", () => {
				if (callsSearchTimer !== null) {
					clearTimeout(callsSearchTimer);
				}
				callsSearchTimer = setTimeout(() => {
					state.callsSearch = callsSearchInput.value;
					state.callsOffset = 0;
					loadCalls().catch((err) => showBanner(err.message, "error"));
				}, 220);
			});

			callsRefreshBtn.addEventListener("click", () => {
				refreshAll();
			});

			callsPrevBtn.addEventListener("click", () => {
				state.callsOffset = Math.max(0, state.callsOffset - PAGE_SIZE);
				loadCalls().catch((err) => showBanner(err.message, "error"));
			});

			callsNextBtn.addEventListener("click", () => {
				state.callsOffset += PAGE_SIZE;
				loadCalls().catch((err) => showBanner(err.message, "error"));
			});

			rulesStatusFilter.addEventListener("change", () => {
				state.rulesStatus = rulesStatusFilter.value;
				loadAllowlist().catch((err) => showBanner(err.message, "error"));
			});

			let rulesSearchTimer = null;
			rulesSearchInput.addEventListener("input", () => {
				if (rulesSearchTimer !== null) {
					clearTimeout(rulesSearchTimer);
				}
				rulesSearchTimer = setTimeout(() => {
					state.rulesSearch = rulesSearchInput.value;
					loadAllowlist().catch((err) => showBanner(err.message, "error"));
				}, 220);
			});

			csvFileInput.addEventListener("change", async () => {
				const file = csvFileInput.files && csvFileInput.files[0];
				if (!file) {
					return;
				}
				try {
					csvTextarea.value = await file.text();
					showBanner("Loaded " + file.name + " into CSV editor. Review and click Import CSV.", "success");
				} catch (err) {
					showBanner(err instanceof Error ? err.message : "Failed to read CSV file", "error");
				}
			});

			csvImportForm.addEventListener("submit", async (event) => {
				event.preventDefault();
				clearBanner();
				const csv = csvTextarea.value;
				if (!csv.trim()) {
					showBanner("Please upload or paste CSV data before importing.", "error");
					return;
				}
				const modeInput = csvImportForm.querySelector('input[name="csv-mode"]:checked');
				const mode = modeInput ? modeInput.value : "merge";
				const submitBtn = document.getElementById("csv-import-btn");
				submitBtn.disabled = true;
				try {
					const result = await apiFetch("/dashboard/api/allowlist/csv", {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({ csv, mode }),
					});
					showBanner(
						"CSV import (" + result.mode + "): " + result.imported + " imported, " + result.updated + " updated, " + result.skippedInvalid + " skipped.",
						"success",
					);
					await Promise.all([loadAllowlist(), loadCalls(), loadSummary()]);
				} catch (err) {
					showBanner(err instanceof Error ? err.message : "CSV import failed", "error");
				} finally {
					submitBtn.disabled = false;
				}
			});

			addRuleForm.addEventListener("submit", async (event) => {
				event.preventDefault();
				clearBanner();
				const phone = rulePhoneInput.value.trim();
				const label = ruleLabelInput.value.trim();
				const status = ruleStatusSelect.value === "blocked" ? "blocked" : "allowed";
				const submitBtn = document.getElementById("add-rule-btn");
				submitBtn.disabled = true;
				try {
					await apiFetch("/dashboard/api/allowlist", {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({
							phone,
							status,
							permanent: true,
							...(label ? { label } : {}),
						}),
					});
					rulePhoneInput.value = "";
					ruleLabelInput.value = "";
					showBanner("Saved rule for " + phone + ".", "success");
					await Promise.all([loadAllowlist(), loadCalls(), loadSummary()]);
				} catch (err) {
					showBanner(err instanceof Error ? err.message : "Failed to save rule", "error");
				} finally {
					submitBtn.disabled = false;
				}
			});

			refreshAll();
		})();
	</script>
</body>
</html>`;
}
