// src/index.ts
import * as Sentry from "@sentry/cloudflare";
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

	// GitHub Issues configuration
	GITHUB_TOKEN: string; // GitHub Personal Access Token with repo:issues
	GITHUB_REPO: string; // "owner/repo"
	GITHUB_API_BASE?: string; // Optional, for GitHub Enterprise (e.g., https://github.myco.com/api/v3)

	// System app API keys / secrets
	GAMMA_API_KEY?: string;

	// Sentry configuration
	SENTRY_DSN: string;
	SENTRY_ENV?: string;
	CF_VERSION_METADATA: { id: string };
}

// (removed) static host-to-app utility in favor of Pipedream apps index

// (removed) http_request tool and feature flag; rely on proxy_request universally

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

// ---- System Apps (direct auth) ----
type SystemAppAuth = {
	type: "api_key_header";
	header: string;
	valueEnv: string; // Name of Env field holding the secret
};

interface SystemAppConfigEntry {
	appSlug: string;
	allowedDomains: string[]; // hostnames allowed for absolute URLs
	baseUrl: string; // base origin for relative paths (e.g., https://api.example.com/v1)
	auth: SystemAppAuth;
	defaultHeaders?: Record<string, string>;
}

type SystemAppsConfig = SystemAppConfigEntry[];

function getSystemAppsConfig(env: Env): SystemAppsConfig {
	// Initial system apps are hard-coded. This can be extended or loaded from KV later.
	const gamma: SystemAppConfigEntry = {
		appSlug: "gamma",
		allowedDomains: ["public-api.gamma.app"],
		baseUrl: "https://public-api.gamma.app/v0.2",
		auth: {
			type: "api_key_header",
			header: "X-API-KEY",
			valueEnv: "GAMMA_API_KEY",
		},
		defaultHeaders: { Accept: "application/json" },
	};
	return [gamma];
}

function resolveSystemAppFromFullUrl(
	urlStr: string,
	config: SystemAppsConfig,
): SystemAppConfigEntry | undefined {
	let host: string | undefined;
	try {
		host = new URL(urlStr).hostname.toLowerCase();
	} catch {
		return undefined;
	}
	if (!host) return undefined;
	for (const entry of config) {
		if (entry.allowedDomains.some((d) => d === host)) return entry;
		if (entry.allowedDomains.some((d) => host.endsWith(`.${d}`))) return entry;
	}
	return undefined;
}

function buildSystemUrl(inputUrl: string, app: SystemAppConfigEntry): string {
	// If absolute URL, return as-is. Otherwise, resolve against baseUrl.
	if (/^https?:\/\//i.test(inputUrl)) return inputUrl;
	try {
		const base = app.baseUrl.endsWith("/") ? app.baseUrl : `${app.baseUrl}/`;
		const rel = inputUrl.startsWith("/") ? inputUrl.slice(1) : inputUrl;
		return new URL(rel, base).toString();
	} catch {
		return app.baseUrl;
	}
}

async function directSystemRequest(
	env: Env,
	params: {
		method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
		url: string; // may be relative or absolute
		headers?: Record<string, string>;
		body?: unknown;
		app: SystemAppConfigEntry;
	},
): Promise<{ status: number; data: any }> {
	// Validate absolute URLs against allowlist
	const isFullUrl = /^https?:\/\//i.test(params.url);
	if (isFullUrl) {
		try {
			const u = new URL(params.url);
			const host = u.hostname.toLowerCase();
			const allowed = params.app.allowedDomains;
			const ok =
				allowed.includes(host) || allowed.some((d) => host.endsWith(`.${d}`));
			if (!ok) {
				return {
					status: 400,
					data: {
						error: "not_allowed_for_system_app",
						message: `The URL host '${host}' is not allowed for system app '${params.app.appSlug}'.`,
						allowed_domains: params.app.allowedDomains,
					},
				};
			}
		} catch {}
	}

	const finalUrl = buildSystemUrl(params.url, params.app);

	// Prepare headers
	const headers: Record<string, string> = {};
	const userHeaders = sanitizeProxyHeaders(params.headers);
	if (userHeaders) Object.assign(headers, userHeaders);
	// Remove potentially conflicting auth
	for (const k of Object.keys(headers)) {
		if (k.toLowerCase() === "authorization") delete headers[k];
	}

	// Inject auth
	switch (params.app.auth.type) {
		case "api_key_header": {
			const envKey = params.app.auth.valueEnv;
			const secret = (env as any)[envKey] as string | undefined;
			if (!secret) {
				return {
					status: 500,
					data: {
						error: "system_secret_missing",
						message: `Missing secret '${envKey}' for system app '${params.app.appSlug}'.`,
					},
				};
			}
			headers[params.app.auth.header] = secret;
			break;
		}
	}

	if (!headers["Accept"]) headers["Accept"] = "application/json";
	if (params.app.defaultHeaders)
		Object.assign(headers, params.app.defaultHeaders);

	// Body handling
	let bodyToSend: BodyInit | null = null;
	if (params.body !== undefined) {
		if (typeof params.body === "string") {
			bodyToSend = params.body as string;
			if (!headers["Content-Type"]) headers["Content-Type"] = "text/plain";
		} else {
			bodyToSend = JSON.stringify(params.body);
			if (!headers["Content-Type"])
				headers["Content-Type"] = "application/json";
		}
	}

	const resp = await fetch(finalUrl, {
		method: params.method,
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

// (removed) Xero tenant helper; proxy_request path is now canonical

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

	// Helper to sanitize args for Sentry breadcrumbs
	private sanitizeArgs(args: unknown) {
		try {
			const clone = JSON.parse(JSON.stringify(args ?? {}));
			const scrub = (o: any) => {
				if (!o || typeof o !== "object") return;
				for (const k of Object.keys(o)) {
					if (
						/(authorization|access[_-]?token|refresh[_-]?token|client[_-]?secret)/i.test(
							k,
						)
					) {
						o[k] = "[redacted]";
					} else {
						scrub(o[k]);
					}
				}
			};
			scrub(clone);
			return clone;
		} catch {
			return {};
		}
	}

	// Helper to add Sentry instrumentation to a tool handler
	private withSentryInstrumentation<TArgs>(
		toolName: string,
		deriveApp: (args: TArgs) => string | undefined,
		handler: (args: TArgs) => Promise<{ content: any[] }>,
	) {
		return async (args: TArgs) => {
			const sub = this.props?.sub as string | undefined;
			const email = (this.props?.email as string | undefined) || undefined;
			const app = deriveApp(args);

			// Safely attempt Sentry operations with fallback
			const safeSentryCall = (operation: () => void) => {
				try {
					if (this.env.SENTRY_DSN) {
						operation();
					}
				} catch (error) {
					// Silent fallback - don't break the request if Sentry fails
					console.warn(`Sentry operation failed:`, error);
				}
			};

			// Attach user/app to scope for this call
			safeSentryCall(() => {
				Sentry.setUser(email ? { id: sub, email } : { id: sub ?? "unknown" });
				Sentry.setTag("tool", toolName);
				if (app) Sentry.setTag("app", app);
			});

			// Breadcrumb with sanitized inputs
			safeSentryCall(() => {
				Sentry.addBreadcrumb({
					category: "mcp.tool.called",
					level: "info",
					data: { tool: toolName, app, args: this.sanitizeArgs(args) },
				});
			});

			// One transaction-like span per tool call (with fallback)
			if (this.env.SENTRY_DSN) {
				try {
					return await Sentry.startSpan(
						{
							name: `mcp.tool/${toolName}`,
							op: "mcp.tool",
							forceTransaction: true,
							attributes: {
								"mcp.user.sub": sub ?? "unknown",
								...(app ? { "mcp.app": app } : {}),
							},
						},
						async () => {
							try {
								const result = await handler(args);
								return result;
							} catch (err) {
								// Try to capture error, but don't fail if Sentry is down
								let eventId = "unavailable";
								safeSentryCall(() => {
									eventId = Sentry.captureException(err, {
										tags: { tool: toolName, app },
									});
								});
								return {
									content: [
										{
											type: "text",
											text: JSON.stringify({ error: "internal_error", eventId }),
										},
									],
								};
							}
						},
					);
				} catch (sentryError) {
					console.warn(`Sentry span creation failed, falling back to direct execution:`, sentryError);
					// Fallback to direct execution without Sentry
				}
			}
			
			// Direct execution fallback (when Sentry is unavailable or disabled)
			try {
				const result = await handler(args);
				return result;
			} catch (err) {
				// Log error locally when Sentry is unavailable
				console.error(`Tool ${toolName} error:`, err);
				return {
					content: [
						{
							type: "text", 
							text: JSON.stringify({ error: "internal_error", eventId: "sentry_unavailable" })
						},
					],
				};
			}
		};
	}

	async init() {
		// ---- Helper: GitHub issue creation ----
		const createGithubIssue = async (
			title: string,
			body: string,
		): Promise<
			{ html_url?: string; number?: number; error?: string } | undefined
		> => {
			const token = this.env.GITHUB_TOKEN;
			const repo = this.env.GITHUB_REPO;
			if (!token || !repo) return { error: "GitHub not configured" } as any;
			const apiBase = this.env.GITHUB_API_BASE || "https://api.github.com";
			const url = `${apiBase.replace(/\/$/, "")}/repos/${repo}/issues`;
			const resp = await fetch(url, {
				method: "POST",
				headers: {
					Authorization: `Bearer ${token}`,
					Accept: "application/vnd.github+json",
					"Content-Type": "application/json",
					"X-GitHub-Api-Version": "2022-11-28",
					"User-Agent": "asi-mcp-worker/1.0",
				},
				body: JSON.stringify({ title, body }),
			});
			if (!resp.ok) {
				let message = `GitHub error ${resp.status}`;
				try {
					const text = await resp.text();
					try {
						const j: any = JSON.parse(text);
						message = j?.message || message;
					} catch {
						if (text) message = `${message}: ${text.substring(0, 300)}`;
					}
				} catch {}
				return { error: message } as any;
			}
			return resp.json();
		};
		// -------- auth_status --------
		this.server.tool(
			"auth_status",
			{},
			this.withSentryInstrumentation(
				"auth_status",
				() => undefined, // no single app
				async () => {
					const external_user_id = this.getExternalUserId();
					const pdToken = await getPdAccessToken(this.env);
					const res = await listAccountsForUser(
						this.env,
						pdToken,
						external_user_id,
						undefined,
						false,
					);

					const data = (res.data || []).map((a) => ({
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
			),
		);

		// -------- auth_connect --------
		this.server.tool(
			"auth_connect",
			{
				app: z.string().optional(),
			},
			this.withSentryInstrumentation(
				"auth_connect",
				(args) => args.app,
				async ({ app }: { app?: string }) => {
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
			),
		);

		// -------- auth_disconnect --------
		this.server.tool(
			"auth_disconnect",
			{
				app: z.string().optional(),
				account_id: z.string().optional(),
			},
			this.withSentryInstrumentation(
				"auth_disconnect",
				(args) => args.app,
				async ({ app, account_id }: { app?: string; account_id?: string }) => {
					const external_user_id = this.getExternalUserId();
					const pdToken = await getPdAccessToken(this.env);

					// Require at least one discriminator to avoid ambiguity across apps
					if (!account_id && !app) {
						return {
							content: [
								{
									type: "text",
									text: "Provide either account_id or app to disconnect.",
								},
							],
						};
					}

					let acctId = account_id;
					if (!acctId) {
						const listed = await listAccountsForUser(
							this.env,
							pdToken,
							external_user_id,
							app,
						);
						// Filter accounts to ensure we only get accounts for the specified app
						const matchingAccounts = (listed?.data || []).filter(
							(account) => account.app?.name_slug === app,
						);
						acctId = matchingAccounts[0]?.id;
					}
					if (!acctId) {
						return {
							content: [
								{
									type: "text",
									text: `No account found for app ${app || "(unspecified)"}.`,
								},
							],
						};
					}
					await deleteAccount(this.env, pdToken, acctId);

					// Clean per-app cache (currently only Xero uses tenant cache)
					let resolvedApp = app;
					if (!resolvedApp) {
						try {
							const detailed: any = await getAccountWithCredentials(
								this.env,
								pdToken,
								acctId,
							);
							resolvedApp = detailed?.data?.app?.name_slug;
						} catch {}
					}
					if (resolvedApp === "xero") {
						await this.env.USER_LINKS.delete(`xero-tenant:${external_user_id}`);
					}

					return {
						content: [
							{
								type: "text",
								text: `Disconnected ${resolvedApp || "account"}.`,
							},
						],
					};
				},
			),
		);

		// -------- auth_apps --------
		this.server.tool(
			"auth_apps",
			{},
			this.withSentryInstrumentation(
				"auth_apps",
				() => undefined, // no single app
				async () => {
					const pdToken = await getPdAccessToken(this.env);
					const index = await fetchProxyEnabledApps(this.env, pdToken);
					return {
						content: [
							{
								type: "text",
								text: JSON.stringify(index),
							},
						],
					};
				},
			),
		);

		// (removed) http_request tool

		// -------- proxy_request --------
		this.server.tool(
			"proxy_request",
			{
				method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
				url: z.string(),
				headers: z.record(z.string()).optional(),
				body: z.union([z.string(), z.record(z.any())]).optional(),
				account_id: z.string().optional(),
				app: z.string().optional(),
				provider: z.enum(["system", "pipedream"]).optional(),
			},
			this.withSentryInstrumentation(
				"proxy_request",
				(args) => {
					// Try to derive app from args.app or detect from URL
					if (args.app) return args.app;
					const isFullUrl = /^https?:\/\//i.test(args.url);
					if (isFullUrl) {
						try {
							const host = new URL(args.url).hostname.toLowerCase();
							// This is a simplified detection - the full logic is in the handler
							if (host.includes("hubspot")) return "hubspot";
							if (host.includes("xero")) return "xero";
							if (host.includes("pandadoc")) return "pandadoc";
							if (host.includes("gamma")) return "gamma";
						} catch {}
					}
					return undefined;
				},
				async ({
					method,
					url,
					headers,
					body,
					account_id,
					app,
					provider,
				}: {
					method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
					url: string;
					headers?: Record<string, string>;
					body?: string | Record<string, unknown>;
					account_id?: string;
					app?: string;
					provider?: "system" | "pipedream";
				}) => {
					const external_user_id = this.getExternalUserId();

					// System apps resolution
					const systemApps = getSystemAppsConfig(this.env);
					const systemAppBySlug = app
						? systemApps.find((e) => e.appSlug === app)
						: undefined;
					const isFullUrl = /^https?:\/\//i.test(url);
					const systemAppByUrl =
						!systemAppBySlug && isFullUrl
							? resolveSystemAppFromFullUrl(url, systemApps)
							: undefined;
					const selectedSystemApp = systemAppBySlug || systemAppByUrl;

					// If explicitly requested system provider, enforce resolution
					if (provider === "system") {
						if (!selectedSystemApp) {
							return {
								content: [
									{
										type: "text",
										text: JSON.stringify({
											error: "system_app_required",
											message:
												"Provider set to system, but no matching system app found. Pass app or use a URL matching an allowed domain.",
											allowed_system_apps: systemApps.map((e) => e.appSlug),
										}),
									},
								],
							};
						}
						const sysResult = await directSystemRequest(this.env, {
							method,
							url,
							headers,
							body:
								typeof body === "string"
									? (() => {
											try {
												return JSON.parse(body);
											} catch {
												return body;
											}
										})()
									: body,
							app: selectedSystemApp,
						});
						return {
							content: [
								{
									type: "text",
									text: JSON.stringify({
										provider: "system",
										app: selectedSystemApp.appSlug,
										...sysResult,
									}),
								},
							],
						};
					}

					// Lazy-fetch Pipedream token only if needed
					let pdToken: string | undefined;

					// Resolve app slug dynamically when possible
					let resolvedApp = app;
					if (!resolvedApp && isFullUrl) {
						try {
							pdToken = pdToken || (await getPdAccessToken(this.env));
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

					// Prefer system app if available and no explicit account_id or provider override
					if (!account_id && !provider && selectedSystemApp) {
						const sysResult = await directSystemRequest(this.env, {
							method,
							url,
							headers,
							body:
								typeof body === "string"
									? (() => {
											try {
												return JSON.parse(body);
											} catch {
												return body;
											}
										})()
									: body,
							app: selectedSystemApp,
						});
						return {
							content: [
								{
									type: "text",
									text: JSON.stringify({
										provider: "system",
										app: selectedSystemApp.appSlug,
										...sysResult,
									}),
								},
							],
						};
					}

					// If account_id provided but app still unknown, derive app from account details
					if (!resolvedApp && account_id) {
						try {
							pdToken = pdToken || (await getPdAccessToken(this.env));
							const detailed: any = await getAccountWithCredentials(
								this.env,
								pdToken,
								account_id,
							);
							const slug = detailed?.data?.app?.name_slug;
							if (slug) resolvedApp = slug;
						} catch {}
					}

					// If we still can't resolve an app, this destination isn't supported by the proxy
					if (!resolvedApp) {
						let supported: string[] = [];
						try {
							pdToken = pdToken || (await getPdAccessToken(this.env));
							const index = await fetchProxyEnabledApps(this.env, pdToken);
							supported = index.map((e) => e.appSlug);
						} catch {}
						return {
							content: [
								{
									type: "text",
									text: JSON.stringify({
										error: "unsupported_destination",
										message:
											"This URL does not map to a supported Pipedream Connect app for this project.",
										url,
										supported_apps: supported,
										action:
											"Pass the app parameter and a relative path (e.g., '/crm/v3/...'), or use auth.connect to add support.",
										note: "Tip: Use the send_feedback tool to report unsupported API requests.",
									}),
								},
							],
						};
					}

					// Resolve account
					let acctId = account_id;
					if (!acctId) {
						pdToken = pdToken || (await getPdAccessToken(this.env));
						const listed = await listAccountsForUser(
							this.env,
							pdToken,
							external_user_id,
							resolvedApp,
							false,
						);
						// Filter accounts to ensure we only get accounts for the resolved app
						// This is defensive programming in case the API doesn't filter properly
						const matchingAccounts = (listed?.data || []).filter(
							(account) => account.app?.name_slug === resolvedApp,
						);
						acctId = matchingAccounts[0]?.id;
					}
					if (!acctId) {
						pdToken = pdToken || (await getPdAccessToken(this.env));
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

					pdToken = pdToken || (await getPdAccessToken(this.env));

					// Add nested span for the actual HTTP request (with fallback)
					let result: any;
					const executeProxyRequest = async () => {
						const resp = await proxyRequest(this.env, pdToken!, {
							external_user_id,
							account_id: acctId,
							method,
							url,
							headers,
							body: proxyBody,
						});

						// Safely add breadcrumb with response info
						try {
							if (this.env.SENTRY_DSN) {
								Sentry.addBreadcrumb({
									category: "mcp.proxy.response",
									level:
										resp.status >= 500
											? "error"
											: resp.status >= 400
												? "warning"
												: "info",
									data: {
										status: resp.status,
										app: resolvedApp,
										host: isFullUrl ? new URL(url).hostname : "api.pipedream.com",
									},
								});
							}
						} catch (sentryError) {
							console.warn(`Sentry breadcrumb failed:`, sentryError);
						}

						return resp;
					};

					if (this.env.SENTRY_DSN) {
						try {
							result = await Sentry.startSpan(
								{
									name: "mcp.proxy.request",
									op: "http.client",
									attributes: {
										"http.method": method,
										"http.url": new URL(url, "https://example.com").origin, // avoid path params in spans
										"dest.host": isFullUrl
											? new URL(url).hostname
											: "api.pipedream.com",
										"mcp.app": resolvedApp ?? "unknown",
									},
								},
								executeProxyRequest,
							);
						} catch (sentryError) {
							console.warn(`Sentry HTTP span failed, falling back to direct execution:`, sentryError);
							result = await executeProxyRequest();
						}
					} else {
						result = await executeProxyRequest();
					}

					// Intercept common mismatch error to provide clearer guidance
					if (
						result?.status === 400 &&
						(result as any)?.data?.error?.domain &&
						String((result as any).data.error.domain)
							.toLowerCase()
							.includes("not allowed")
					) {
						let allowed: string[] | undefined;
						try {
							pdToken = pdToken || (await getPdAccessToken(this.env));
							const index = await fetchProxyEnabledApps(this.env, pdToken);
							const entry = index.find((e) => e.appSlug === resolvedApp);
							allowed = entry?.allowedDomains;
						} catch {}
						return {
							content: [
								{
									type: "text",
									text: JSON.stringify({
										error: "not_allowed_for_app",
										message: `The URL is not allowed for the selected app. Provide a relative path or target one of the allowed domains for ${resolvedApp}.`,
										app: resolvedApp,
										account_id: acctId,
										url,
										allowed_domains: allowed,
									}),
								},
							],
						};
					}

					return {
						content: [
							{
								type: "text",
								text: JSON.stringify({
									app: resolvedApp,
									account_id: acctId,
									...result,
								}),
							},
						],
					};
				},
			),
		);

		// -------- send_feedback --------
		this.server.tool(
			"send_feedback",
			{
				title: z.string().min(4).max(120),
				message: z.string().min(10).max(4000),
				context: z
					.object({
						app: z.string().optional(),
						url: z.string().optional(),
						tool: z.string().optional(),
						payload: z.any().optional(),
					})
					.optional(),
			},
			this.withSentryInstrumentation(
				"send_feedback",
				(args) => args.context?.app,
				async ({
					title,
					message,
					context,
				}: {
					title: string;
					message: string;
					context?: any;
				}) => {
					const userId = this.getExternalUserId();
					const email = this.props?.email || "";
					const name = this.props?.name || "";
					const when = new Date().toISOString();

					const bodyLines = [
						`Reporter: ${name || "(unknown)"} <${email || ""}>`,
						`User ID: ${userId}`,
						`When: ${when}`,
						"",
						"Message:",
						"" + message,
					];
					if (context) {
						bodyLines.push("", "Context:");
						try {
							bodyLines.push(
								"```json\n" + JSON.stringify(context, null, 2) + "\n```",
							);
						} catch {
							bodyLines.push("(context not serializable)");
						}
					}

					const issue = await createGithubIssue(title, bodyLines.join("\n"));
					if (!issue || (issue as any).error) {
						return {
							content: [
								{
									type: "text",
									text: JSON.stringify({
										ok: false,
										error: (issue as any)?.error || "Unknown error",
									}),
								},
							],
						};
					}
					return {
						content: [
							{
								type: "text",
								text: JSON.stringify({
									ok: true,
									issue_number: (issue as any).number,
									issue_url: (issue as any).html_url,
								}),
							},
						],
					};
				},
			),
		);
	}
}

// Helper to redact secrets from any Sentry payload
function scrubEvent(event: Sentry.Event): Sentry.Event {
	const redact = (obj: any) => {
		if (!obj || typeof obj !== "object") return;
		for (const k of Object.keys(obj)) {
			if (
				/(authorization|access[_-]?token|refresh[_-]?token|client[_-]?secret)/i.test(
					k,
				)
			) {
				obj[k] = "[redacted]";
			} else {
				redact(obj[k]);
			}
		}
	};
	redact((event as any).request);
	redact(event.contexts);
	redact(event.extra);
	redact((event as any).breadcrumbs);
	return event;
}

// Create the OAuth Provider instance
const provider = new OAuthProvider({
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

// Helper to safely wrap with Sentry or fallback gracefully
function createSentryWrappedHandler(
	provider: unknown,
): ExportedHandler<Env> {
	return {
		fetch: async (request, env, ctx) => {
			// Check if Sentry should be enabled
			if (!env.SENTRY_DSN) {
				console.log("Sentry DSN not configured, running without Sentry monitoring");
				return (provider as any).fetch(request, env, ctx);
			}

			try {
				// Try to wrap with Sentry
				const sentryWrapped = Sentry.withSentry(
					(env: Env) => {
						const { id: versionId } = env.CF_VERSION_METADATA || { id: "dev" };
						return {
							dsn: env.SENTRY_DSN,
							environment: env.SENTRY_ENV ?? env.PIPEDREAM_ENV,
							release: versionId,
							// capture headers/IP (you can set this false if you prefer)
							sendDefaultPii: true,
							// Logs: forwards console.* to Sentry Logs  
							enableLogs: true,
							// Tracing: 100% since volume is low (tune later)
							tracesSampleRate: 1.0,
							// Belt & suspenders token-scrubber
							beforeSend: scrubEvent as any,
						};
					},
					provider as unknown as ExportedHandler<Env>,
				);
				if (sentryWrapped?.fetch) {
					return await sentryWrapped.fetch(request, env, ctx);
				}
				throw new Error("Sentry wrapper did not return expected handler");
			} catch (sentryError) {
				console.error("Sentry initialization failed, falling back to direct execution:", sentryError);
				// Fallback to direct provider execution
				return (provider as any).fetch(request, env, ctx);
			}
		},
	};
}

// Export the OAuth Provider with resilient Sentry wrapper
export default createSentryWrappedHandler(provider);
