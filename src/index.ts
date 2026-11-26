import { handleAdminRequest } from "./handlers/admin.ts";
import { handleDashboardRequest } from "./handlers/dashboard.ts";
import { handleVoiceRequest } from "./handlers/voice.ts";
import { withSecurityHeaders } from "./security/http.ts";
import { buildHangupTwiml } from "./twiml/builder.ts";
import type { CallFirewallEnv, ExecutionWaitUntil } from "./types.ts";

/**
 * Primary Cloudflare Worker entrypoint for You Shall Not Ring.
 *
 * Why top-level exception isolation: Returning silent `<Hangup/>` on unhandled
 * `/voice/*` errors stops Twilio from speaking a generic application-error prompt
 * to spam callers, while still logging diagnostic context to Workers Logs.
 */
export default {
	async fetch(
		request: Request,
		env: CallFirewallEnv,
		ctx?: ExecutionWaitUntil,
	): Promise<Response> {
		const url = new URL(request.url);

		try {
			if (url.pathname === "/health" && request.method === "GET") {
				return new Response(
					JSON.stringify({
						ok: true,
						service: "you-shall-not-ring",
					}),
					{
						status: 200,
						headers: withSecurityHeaders({
							"Content-Type": "application/json; charset=utf-8",
							"Cache-Control": "no-store",
						}),
					},
				);
			}

			if (url.pathname.startsWith("/voice/")) {
				return await handleVoiceRequest(request, env, url, ctx);
			}

			if (url.pathname.startsWith("/admin/")) {
				return await handleAdminRequest(request, env, url);
			}

			if (url.pathname === "/dashboard" || url.pathname.startsWith("/dashboard/")) {
				return await handleDashboardRequest(request, env, url);
			}

			return new Response("Not Found", {
				status: 404,
				headers: withSecurityHeaders({ "Cache-Control": "no-store" }),
			});
		} catch (error) {
			console.error(`Unhandled error handling ${request.method} ${url.pathname}`, error);
			if (url.pathname.startsWith("/voice/")) {
				return buildHangupTwiml();
			}
			return new Response(JSON.stringify({ error: "Internal Server Error" }), {
				status: 500,
				headers: withSecurityHeaders({
					"Content-Type": "application/json; charset=utf-8",
					"Cache-Control": "no-store",
				}),
			});
		}
	},
} satisfies ExportedHandler<Cloudflare.Env>;
