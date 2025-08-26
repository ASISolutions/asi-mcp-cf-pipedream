// src/index.ts
import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { z } from "zod";
import AccessDefaultHandler from "./access-handler";
import type { Props } from "./workers-oauth-utils";

// ---- Environment Types ----
export interface Env {
	// OAuth KV storage
	OAUTH_KV: KVNamespace;
	// User data and caching
	USER_LINKS: KVNamespace;

	// Cloudflare Access OAuth configuration
	ACCESS_CLIENT_ID: string;
	ACCESS_CLIENT_SECRET: string;
	ACCESS_TOKEN_URL: string;
	ACCESS_AUTHORIZATION_URL: string;
	ACCESS_JWKS_URL: string;
	COOKIE_ENCRYPTION_KEY: string;

	// Pipedream Connect configuration
	PIPEDREAM_CLIENT_ID: string;
	PIPEDREAM_CLIENT_SECRET: string;
	PIPEDREAM_PROJECT_ID: string; // proj_xxx
	PIPEDREAM_ENV: "development" | "production";

	// Optional redirect URIs for Connect links:
	CONNECT_SUCCESS_REDIRECT?: string;
	CONNECT_ERROR_REDIRECT?: string;

	// MCP Durable Object
	MCP_OBJECT: DurableObjectNamespace;
}

// ---- Utility: detect app slug from URL hostname ----
const HOST_TO_APP: Record<string, string> = {
	"api.hubapi.com": "hubspot",
	"api.pandadoc.com": "pandadoc",
	"api.xero.com": "xero",
};
function detectAppSlugFromUrl(urlStr: string): string | undefined {
	const host = new URL(urlStr).hostname.toLowerCase();
	if (HOST_TO_APP[host]) return HOST_TO_APP[host];
	// Allow broader matching for HubSpot multi-domains:
	if (host.endsWith("hubapi.com")) return "hubspot";
	return undefined;
}

// ---- Dynamic Pipedream Apps cache (for host->app detection) ----
interface PdAppInfo {
	name_slug: string;
	connect?: {
		proxy_enabled?: boolean;
		allowed_domains?: string[];
		base_proxy_target_url?: string;
	};
}

interface AppsIndexEntry {
	appSlug: string;
	allowedDomains: string[];
	isDynamic: boolean; // base_proxy_target_url contains placeholders like {{...}}
}

type AppsIndex = AppsIndexEntry[];

let IN_MEMORY_APPS_INDEX: { expiresAt: number; data: AppsIndex } | undefined;

async function fetchProxyEnabledApps(
	env: Env,
	pdToken: string,
): Promise<AppsIndex> {
	// In-memory cache (best-effort; may be evicted across cold starts)
	const now = Date.now();
	if (IN_MEMORY_APPS_INDEX && IN_MEMORY_APPS_INDEX.expiresAt > now) {
		return IN_MEMORY_APPS_INDEX.data;
	}

	// KV cache fallback
	const kvKey = "pd:apps:index";
	try {
		const cached = await env.USER_LINKS.get(kvKey);
		if (cached) {
			const parsed = JSON.parse(cached) as {
				expiresAt: number;
				data: AppsIndex;
			};
			if (parsed && parsed.expiresAt > now) {
				IN_MEMORY_APPS_INDEX = parsed;
				return parsed.data;
			}
		}
	} catch {}

	// Fetch from Pipedream REST API
	const res = await fetch("https://api.pipedream.com/v1/apps", {
		headers: {
			Authorization: `Bearer ${pdToken}`,
			"x-pd-environment": env.PIPEDREAM_ENV,
		},
	});
	if (!res.ok) throw new Error(`Pipedream apps list error ${res.status}`);
	const body = (await res.json()) as { data?: PdAppInfo[] };
	const apps = (body.data || []).filter((a) => a.connect?.proxy_enabled);

	const index: AppsIndex = apps.map((a) => {
		const allowed = (a.connect?.allowed_domains || []).map((d) =>
			d.toLowerCase(),
		);
		const baseUrl = a.connect?.base_proxy_target_url || "";
		const isDynamic = /\{\{[^}]+\}\}/.test(baseUrl);
		// For static apps, if no allowed_domains are present, infer host from base URL
		if (!isDynamic && allowed.length === 0) {
			try {
				const u = new URL(baseUrl);
				if (u.hostname) allowed.push(u.hostname.toLowerCase());
			} catch {}
		}
		return {
			appSlug: a.name_slug,
			allowedDomains: allowed,
			isDynamic,
		};
	});

	const expiresAt = now + 15 * 60 * 1000; // 15 minutes
	IN_MEMORY_APPS_INDEX = { expiresAt, data: index };
	try {
		await env.USER_LINKS.put(
			kvKey,
			JSON.stringify({ expiresAt, data: index }),
			{ expirationTtl: 30 * 60 },
		);
	} catch {}
	return index;
}

function resolveAppFromFullUrl(
	urlStr: string,
	index: AppsIndex,
): { app?: string; dynamic?: boolean } {
	let host: string | undefined;
	try {
		host = new URL(urlStr).hostname.toLowerCase();
	} catch {
		return {};
	}
	if (!host) return {};

	// Prefer exact match, then suffix match
	let best: AppsIndexEntry | undefined;
	for (const entry of index) {
		if (entry.allowedDomains.some((d) => d === host)) {
			best = entry;
			break;
		}
	}
	if (!best) {
		for (const entry of index) {
			if (entry.allowedDomains.some((d) => host?.endsWith(`.${d}`))) {
				best = entry;
				break;
			}
		}
	}
	return best ? { app: best.appSlug, dynamic: best.isDynamic } : {};
}

// ---- Pipedream Connect helpers ----
async function getPdAccessToken(env: Env): Promise<string> {
	// You can cache this in-memory between requests, but Workers may cold start.
	const res = await fetch("https://api.pipedream.com/v1/oauth/token", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			grant_type: "client_credentials",
			client_id: env.PIPEDREAM_CLIENT_ID,
			client_secret: env.PIPEDREAM_CLIENT_SECRET,
		}),
	});
	if (!res.ok) throw new Error(`Pipedream token error ${res.status}`);
	const data = (await res.json()) as { access_token: string };
	return data.access_token;
}

async function listAccountsForUser(
	env: Env,
	pdToken: string,
	external_user_id: string,
	appSlug?: string,
	includeCredentials = false,
): Promise<{
	data?: Array<{
		app?: { name_slug: string };
		id: string;
		healthy: boolean;
		dead: boolean;
		expires_at?: string;
		last_refreshed_at?: string;
		next_refresh_at?: string;
		credentials?: Record<string, unknown>;
	}>;
}> {
	const params = new URLSearchParams({ external_user_id });
	if (appSlug) params.set("app_id", appSlug);
	if (includeCredentials) params.set("include_credentials", "true");
	const res = await fetch(
		`https://api.pipedream.com/v1/connect/${env.PIPEDREAM_PROJECT_ID}/accounts?${params.toString()}`,
		{
			headers: {
				Authorization: `Bearer ${pdToken}`,
				"x-pd-environment": env.PIPEDREAM_ENV,
			},
		},
	);
	if (!res.ok) throw new Error(`Pipedream list accounts ${res.status}`);
	return res.json();
}

async function getAccountWithCredentials(
	env: Env,
	pdToken: string,
	account_id: string,
) {
	const url = `https://api.pipedream.com/v1/connect/${env.PIPEDREAM_PROJECT_ID}/accounts/${account_id}?include_credentials=true`;
	const res = await fetch(url, {
		headers: {
			Authorization: `Bearer ${pdToken}`,
			"x-pd-environment": env.PIPEDREAM_ENV,
		},
	});
	if (!res.ok) throw new Error(`Pipedream retrieve account ${res.status}`);
	return res.json();
}

async function createConnectLink(
	env: Env,
	pdToken: string,
	external_user_id: string,
	appSlug?: string,
): Promise<string> {
	const res = await fetch(
		`https://api.pipedream.com/v1/connect/${env.PIPEDREAM_PROJECT_ID}/tokens`,
		{
			method: "POST",
			headers: {
				Authorization: `Bearer ${pdToken}`,
				"x-pd-environment": env.PIPEDREAM_ENV,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({
				external_user_id,
				success_redirect_uri: env.CONNECT_SUCCESS_REDIRECT,
				error_redirect_uri: env.CONNECT_ERROR_REDIRECT,
			}),
		},
	);
	if (!res.ok) throw new Error(`Pipedream connect token ${res.status}`);
	const tk = (await res.json()) as { connect_link_url: string };
	// Per docs: append ?app={slug} to connect_link_url when known
	const url = new URL(tk.connect_link_url);
	url.searchParams.set("connectLink", "true");
	if (appSlug) url.searchParams.set("app", appSlug);
	return url.toString();
}

async function deleteAccount(
	env: Env,
	pdToken: string,
	account_id: string,
): Promise<void> {
	const url = `https://api.pipedream.com/v1/connect/${env.PIPEDREAM_PROJECT_ID}/accounts/${account_id}`;
	const res = await fetch(url, {
		method: "DELETE",
		headers: {
			Authorization: `Bearer ${pdToken}`,
			"x-pd-environment": env.PIPEDREAM_ENV,
		},
	});
	if (res.status !== 204)
		throw new Error(`Delete account failed ${res.status}`);
}

// ---- Pipedream Connect Proxy helpers ----
function base64UrlEncode(input: string): string {
	// URL-safe Base64 without padding, per Pipedream proxy docs
	const utf8 = new TextEncoder().encode(input);
	let binary = "";
	utf8.forEach((b) => (binary += String.fromCharCode(b)));
	const b64 = btoa(binary);
	return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

const RESTRICTED_PROXY_HEADERS = new Set([
	"accept-encoding",
	"access-control-request-headers",
	"access-control-request-method",
	"connection",
	"content-length",
	"cookie",
	"date",
	"dnt",
	"expect",
	"host",
	"keep-alive",
	"origin",
	"permissions-policy",
	"referer",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"via",
	"note",
]);

function sanitizeProxyHeaders(
	headers?: Record<string, string>,
): Record<string, string> | undefined {
	if (!headers) return undefined;
	const out: Record<string, string> = {};
	for (const [k, v] of Object.entries(headers)) {
		const lower = k.toLowerCase();
		if (RESTRICTED_PROXY_HEADERS.has(lower)) continue;
		if (lower.startsWith("proxy-") || lower.startsWith("sec-")) continue;
		out[k] = v;
	}
	return out;
}

async function proxyRequest(
	env: Env,
	pdToken: string,
	params: {
		external_user_id: string;
		account_id: string;
		method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
		url: string;
		headers?: Record<string, string>;
		body?: unknown;
	},
): Promise<any> {
	const encoded = base64UrlEncode(params.url);
	const qs = new URLSearchParams({
		external_user_id: params.external_user_id,
		account_id: params.account_id,
	});
	const endpoint = `https://api.pipedream.com/v1/connect/${env.PIPEDREAM_PROJECT_ID}/proxy/${encoded}?${qs.toString()}`;

	const headers: Record<string, string> = {
		Authorization: `Bearer ${pdToken}`,
		"x-pd-environment": env.PIPEDREAM_ENV,
	};
	// Use override header for non-POST methods to achieve proper upstream semantics
	if (params.method && params.method !== "POST")
		headers["X-HTTP-Method-Override"] = params.method;
	headers["Accept"] = headers["Accept"] || "application/json";
	const cleanHeaders = sanitizeProxyHeaders(params.headers);
	if (cleanHeaders && Object.keys(cleanHeaders).length) {
		Object.assign(headers, cleanHeaders);
	}

	// Always POST to the proxy; include empty JSON object when no body is provided
	let bodyToSend: BodyInit = "{}";
	if (params.body !== undefined) {
		if (typeof params.body === "string") {
			bodyToSend = params.body as string;
			if (!headers["Content-Type"]) headers["Content-Type"] = "text/plain";
		} else {
			bodyToSend = JSON.stringify(params.body);
			if (!headers["Content-Type"])
				headers["Content-Type"] = "application/json";
		}
	} else {
		headers["Content-Type"] = headers["Content-Type"] || "application/json";
	}

	const resp = await fetch(endpoint, {
		method: "POST",
		headers,
		body: bodyToSend,
	});
	const text = await resp.text();
	let data: any;
	try {
		data = JSON.parse(text);
	} catch {
		data = text;
	}
	return { status: resp.status, data };
}

// ---- Xero tenant helper ----
async function ensureXeroTenantId(
	env: Env,
	external_user_id: string,
	accessToken: string,
): Promise<string> {
	// cache tenant in KV for ~6 hours
	const cacheKey = `xero-tenant:${external_user_id}`;
	const cached = await env.USER_LINKS.get(cacheKey);
	if (cached) return cached;

	const resp = await fetch("https://api.xero.com/connections", {
		headers: { Authorization: `Bearer ${accessToken}` },
	});
	if (!resp.ok) throw new Error(`Xero connections ${resp.status}`);
	const arr = await resp.json();
	if (!Array.isArray(arr) || arr.length === 0) {
		throw new Error("No Xero connections found for this user");
	}
	const tenantId = arr[0]?.tenantId;
	if (!tenantId) throw new Error("Missing tenantId from Xero connections");
	await env.USER_LINKS.put(cacheKey, tenantId, { expirationTtl: 21600 }); // 6 hours
	return tenantId;
}

// ---- MCP Server class ----
export class ASIConnectMCP extends McpAgent<Env, unknown, Props> {
	server = new McpServer({ name: "ASI Connect MCP", version: "1.0.0" });

	// Helper to derive a stable user id for Pipedream Connect from OAuth claims
	private getExternalUserId() {
		const sub = this.props?.sub;
		if (!sub) {
			throw new Error("Missing user subject claim; user not authenticated.");
		}
		return sub;
	}

	async init() {
		// -------- auth.status --------
		this.server.tool(
			"auth.status",
			{
				apps: z.array(z.enum(["hubspot", "xero", "pandadoc"])).optional(),
			},
			async ({ apps }: { apps?: ("hubspot" | "xero" | "pandadoc")[] }) => {
				const external_user_id = this.getExternalUserId();
				const pdToken = await getPdAccessToken(this.env);
				const res = await listAccountsForUser(
					this.env,
					pdToken,
					external_user_id,
					undefined,
					false,
				);

				const filter = (data: NonNullable<typeof res.data>) =>
					apps
						? data.filter(
								(a) =>
									a.app?.name_slug &&
									apps.includes(
										a.app.name_slug as "hubspot" | "xero" | "pandadoc",
									),
							)
						: data;

				const data = filter(res.data || []).map((a) => ({
					app: a.app?.name_slug,
					account_id: a.id,
					healthy: a.healthy,
					dead: a.dead,
					expires_at: a.expires_at,
					last_refreshed_at: a.last_refreshed_at,
					next_refresh_at: a.next_refresh_at,
				}));

				return {
					content: [
						{
							type: "text",
							text: JSON.stringify({ external_user_id, accounts: data }),
						},
					],
				};
			},
		);

		// -------- auth.connect --------
		this.server.tool(
			"auth.connect",
			{
				app: z.enum(["hubspot", "xero", "pandadoc"]),
			},
			async ({ app }: { app: "hubspot" | "xero" | "pandadoc" }) => {
				const external_user_id = this.getExternalUserId();
				const pdToken = await getPdAccessToken(this.env);
				const url = await createConnectLink(
					this.env,
					pdToken,
					external_user_id,
					app,
				);
				return {
					content: [
						{
							type: "text",
							text: JSON.stringify({
								app,
								external_user_id,
								connect_url: url,
								note: "Open this URL to connect the account.",
							}),
						},
					],
				};
			},
		);

		// -------- auth.disconnect --------
		this.server.tool(
			"auth.disconnect",
			{
				app: z.enum(["hubspot", "xero", "pandadoc"]),
				account_id: z.string().optional(),
			},
			async ({
				app,
				account_id,
			}: {
				app: "hubspot" | "xero" | "pandadoc";
				account_id?: string;
			}) => {
				const external_user_id = this.getExternalUserId();
				const pdToken = await getPdAccessToken(this.env);

				let acctId = account_id;
				if (!acctId) {
					const listed = await listAccountsForUser(
						this.env,
						pdToken,
						external_user_id,
						app,
					);
					acctId = listed?.data?.[0]?.id;
				}
				if (!acctId) {
					return {
						content: [{ type: "text", text: `No ${app} account found.` }],
					};
				}
				await deleteAccount(this.env, pdToken, acctId);

				// Clean per-app cache
				if (app === "xero") {
					await this.env.USER_LINKS.delete(`xero-tenant:${external_user_id}`);
				}

				return { content: [{ type: "text", text: `Disconnected ${app}.` }] };
			},
		);

		// -------- http.request --------
		this.server.tool(
			"http.request",
			{
				method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
				url: z.string().url(),
				headers: z.record(z.string()).optional(),
				// body can be omitted, string, or an object (we'll JSON.stringify)
				body: z.union([z.string(), z.record(z.any())]).optional(),
			},
			async ({
				method,
				url,
				headers,
				body,
			}: {
				method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
				url: string;
				headers?: Record<string, string>;
				body?: string | Record<string, unknown>;
			}) => {
				const external_user_id = this.getExternalUserId();
				const appSlug = detectAppSlugFromUrl(url);

				if (!appSlug) {
					return {
						content: [
							{
								type: "text",
								text: JSON.stringify({
									error: "unsupported_destination",
									message:
										"This tool currently supports HubSpot (hubapi.com), Xero (api.xero.com), and PandaDoc (api.pandadoc.com).",
								}),
							},
						],
					};
				}

				const pdToken = await getPdAccessToken(this.env);
				const accounts = await listAccountsForUser(
					this.env,
					pdToken,
					external_user_id,
					appSlug,
					true,
				);

				let account = accounts?.data?.[0];
				if (account && !account.credentials) {
					try {
						const detailed: any = await getAccountWithCredentials(
							this.env,
							pdToken,
							account.id,
						);
						if (detailed?.data?.credentials) {
							account = {
								...account,
								credentials: detailed.data.credentials,
							} as any;
						}
					} catch {}
				}

				if (!account || !account.credentials) {
					// Not connected: return Connect URL
					const connectUrl = await createConnectLink(
						this.env,
						pdToken,
						external_user_id,
						appSlug,
					);
					return {
						content: [
							{
								type: "text",
								text: JSON.stringify({
									requires_auth: true,
									app: appSlug,
									connect_url: connectUrl,
								}),
							},
						],
					};
				}

				// Extract access token from Pipedream credentials.
				// (Exact shape can vary per app; most OAuth apps expose `access_token`.)
				const creds = account.credentials as Record<string, unknown>;
				const accessToken =
					(creds?.access_token as string) ||
					(creds?.token as string) ||
					(creds?.oauth_access_token as string);
				if (!accessToken || typeof accessToken !== "string") {
					throw new Error("Missing access token in Pipedream credentials");
				}

				// Compose headers
				const h = new Headers(headers || {});
				h.set("Authorization", `Bearer ${accessToken}`);

				// Xero special case: add xero-tenant-id unless we're calling /connections
				if (appSlug === "xero") {
					const { pathname } = new URL(url);
					if (!/\/connections\/?$/.test(pathname)) {
						const tenantId = await ensureXeroTenantId(
							this.env,
							external_user_id,
							accessToken,
						);
						if (!h.has("xero-tenant-id")) h.set("xero-tenant-id", tenantId);
					}
				}

				// Body handling
				let fetchBody: BodyInit | undefined ;
				if (typeof body === "string") {
					fetchBody = body;
				} else if (body && typeof body === "object") {
					h.set("Content-Type", h.get("Content-Type") || "application/json");
					fetchBody = JSON.stringify(body);
				}

				const resp = await fetch(url, { method, headers: h, body: fetchBody });

				// Prepare output (avoid echoing huge headers)
				const outHeaders: Record<string, string> = {};
				[...resp.headers.entries()]
					.slice(0, 24)
					.forEach(([k, v]) => (outHeaders[k] = v));

				let payload: any;
				const text = await resp.text();
				try {
					payload = JSON.parse(text);
				} catch {
					payload = text;
				}

				return {
					content: [
						{
							type: "text",
							text: JSON.stringify({
								status: resp.status,
								headers: outHeaders,
								data: payload,
							}),
						},
					],
				};
			},
		);

		// -------- proxy.request --------
		this.server.tool(
			"proxy.request",
			{
				method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
				url: z.string(),
				headers: z.record(z.string()).optional(),
				body: z.union([z.string(), z.record(z.any())]).optional(),
				account_id: z.string().optional(),
				app: z.string().optional(),
			},
			async ({
				method,
				url,
				headers,
				body,
				account_id,
				app,
			}: {
				method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
				url: string;
				headers?: Record<string, string>;
				body?: string | Record<string, unknown>;
				account_id?: string;
				app?: string;
			}) => {
				const external_user_id = this.getExternalUserId();
				const pdToken = await getPdAccessToken(this.env);

				// Resolve app slug dynamically when possible
				let resolvedApp = app;
				const isFullUrl = /^https?:\/\//i.test(url);
				if (!resolvedApp && isFullUrl) {
					try {
						const index = await fetchProxyEnabledApps(this.env, pdToken);
						const { app: detectedApp, dynamic } = resolveAppFromFullUrl(
							url,
							index,
						);
						if (detectedApp) resolvedApp = detectedApp;
						// If app is dynamic and a full URL was provided, convert to relative per docs
						if (dynamic) {
							const u = new URL(url);
							const relative = u.pathname + (u.search || "");
							url = relative || "/";
						}
					} catch {}
				}

				// Resolve account
				let acctId = account_id;
				if (!acctId) {
					const listed = await listAccountsForUser(
						this.env,
						pdToken,
						external_user_id,
						resolvedApp,
						false,
					);
					acctId = listed?.data?.[0]?.id;
				}
				if (!acctId) {
					const connectUrl = await createConnectLink(
						this.env,
						pdToken,
						external_user_id,
						resolvedApp,
					);
					return {
						content: [
							{
								type: "text",
								text: JSON.stringify({
									requires_auth: true,
									app: resolvedApp,
									connect_url: connectUrl,
								}),
							},
						],
					};
				}

				// Prepare body
				let proxyBody: unknown = body;
				if (typeof body === "string") {
					try {
						proxyBody = JSON.parse(body);
					} catch {
						proxyBody = body;
					}
				}

				const result = await proxyRequest(this.env, pdToken, {
					external_user_id,
					account_id: acctId,
					method,
					url,
					headers,
					body: proxyBody,
				});

				return {
					content: [
						{
							type: "text",
							text: JSON.stringify(result),
						},
					],
				};
			},
		);
	}
}

// Export the OAuth Provider as the Worker entrypoint.
// This protects the MCP APIs behind OAuth, using Cloudflare Access as SSO at /authorize.
export default new OAuthProvider({
	// Protect both the HTTP and SSE MCP endpoints
	apiHandlers: {
		"/mcp": ASIConnectMCP.serve("/mcp") as any,
		"/sse": ASIConnectMCP.serveSSE("/sse") as any,
	},
	// The UI / SSO flow is handled by Access in our default handler
	defaultHandler: AccessDefaultHandler,
	// OAuth endpoints surfaced by the provider
	authorizeEndpoint: "/authorize",
	tokenEndpoint: "/token",
	clientRegistrationEndpoint: "/register",
	scopesSupported: ["openid", "email", "profile"],
});
