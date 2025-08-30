// src/index.ts
import * as Sentry from "@sentry/cloudflare";
import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { z } from "zod";
import AccessDefaultHandler from "./access-handler";
import type { Props } from "./workers-oauth-utils";
import { SOPSearchService } from "./github-sop-search";
import { DickerDataAuth } from "./dicker-data-auth";
import { GitHubDocService, type UpdateDocParams } from "./github-doc-update";

// ---- Environment Types ----
export interface Env {
	// OAuth KV storage
	OAUTH_KV: KVNamespace;
	// User data and caching (also used for policy storage)
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
	GITHUB_TOKEN: string; // GitHub Personal Access Token with repo:issues and content write permissions
	GITHUB_REPO: string; // "owner/repo"
	GITHUB_API_BASE?: string; // Optional, for GitHub Enterprise (e.g., https://github.myco.com/api/v3)

	// GitHub SOP Documentation configuration
	GITHUB_SOP_OWNER?: string; // SOP docs repository owner (defaults to "ASISolutions")
	GITHUB_SOP_REPO?: string; // SOP docs repository name (defaults to "docs")
	GITHUB_SOP_BRANCH?: string; // SOP docs branch (defaults to "main")

	// System app API keys / secrets
	GAMMA_API_KEY?: string;

	// Dicker Data credentials
	DICKER_DATA_ACCOUNT?: string;
	DICKER_DATA_USERNAME?: string;
	DICKER_DATA_PASSWORD?: string;

	// Sentry configuration
	SENTRY_DSN: string;
	SENTRY_ENV?: string;
	CF_VERSION_METADATA: { id: string };
}

// (removed) static host-to-app utility in favor of Pipedream apps index

// (removed) http_request tool and feature flag; rely on asi_magic_tool universally

// ---- Dynamic Pipedream Apps cache (for host->app detection) ----
interface PdAppInfo {
	name_slug: string;
	name?: string;
	description?: string;
	app_type?: string;
	categories?: string[];
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

	// KV cache fallback - intentionally global as app directory is the same for all tenants
	// Tenant isolation happens at the connection level via external_user_id namespacing
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
	if (!res.ok) {
		console.warn(`Pipedream apps list error ${res.status}`);
		throw new Error("Failed to fetch available apps");
	}
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

// Enhanced search interface for apps
// Enhanced app search result with display-friendly formatting
interface AppSearchResult {
	name_slug: string;
	name?: string;
	description?: string;
	app_type?: string;
	categories?: string[];
	connect_enabled: boolean;
	allowed_domains: string[];
	base_url?: string;
	is_dynamic: boolean;
}

let IN_MEMORY_APPS_SEARCH:
	| { expiresAt: number; data: AppSearchResult[] }
	| undefined;

/**
 * Enhanced search function with caching and comprehensive filtering
 */
async function searchAppsWithCache(
	env: Env,
	pdToken: string,
	query?: string,
	limit = 20,
): Promise<AppSearchResult[]> {
	// In-memory cache (best-effort; may be evicted across cold starts)
	const now = Date.now();
	let allApps: AppSearchResult[] | undefined;

	if (IN_MEMORY_APPS_SEARCH && IN_MEMORY_APPS_SEARCH.expiresAt > now) {
		allApps = IN_MEMORY_APPS_SEARCH.data;
	} else {
		// KV cache fallback
		const kvKey = "pd:apps:search";
		try {
			const cached = await env.USER_LINKS.get(kvKey);
			if (cached) {
				const parsed = JSON.parse(cached) as {
					expiresAt: number;
					data: AppSearchResult[];
				};
				if (parsed && parsed.expiresAt > now) {
					IN_MEMORY_APPS_SEARCH = parsed;
					allApps = parsed.data;
				}
			}
		} catch {}

		if (!allApps) {
			// Fetch from Pipedream REST API with error handling
			try {
				const res = await fetch("https://api.pipedream.com/v1/apps", {
					headers: {
						Authorization: `Bearer ${pdToken}`,
					},
				});
				if (!res.ok) {
					console.warn(`Pipedream apps API error ${res.status}`);
					throw new Error("Failed to fetch apps data");
				}
				const body = (await res.json()) as { data?: PdAppInfo[] };
				const apps = body.data || [];

				// Transform to search-friendly format
				allApps = apps.map((a) => {
					const allowed = (a.connect?.allowed_domains || []).map((d) =>
						d.toLowerCase(),
					);
					const baseUrl = a.connect?.base_proxy_target_url || "";
					const isDynamic = /\{\{[^}]+\}\}/.test(baseUrl);
					// For static apps, if no allowed_domains are present, infer host from base URL
					if (!isDynamic && allowed.length === 0 && baseUrl) {
						try {
							const u = new URL(baseUrl);
							if (u.hostname) allowed.push(u.hostname.toLowerCase());
						} catch {}
					}
					return {
						name_slug: a.name_slug,
						name: a.name,
						description: a.description,
						app_type: a.app_type,
						categories: a.categories,
						connect_enabled: !!a.connect?.proxy_enabled,
						allowed_domains: allowed,
						base_url: baseUrl,
						is_dynamic: isDynamic,
					};
				});

				const expiresAt = now + 15 * 60 * 1000; // 15 minutes
				IN_MEMORY_APPS_SEARCH = { expiresAt, data: allApps };
				try {
					await env.USER_LINKS.put(
						kvKey,
						JSON.stringify({ expiresAt, data: allApps }),
						{ expirationTtl: 30 * 60 },
					);
				} catch {}
			} catch (error) {
				console.warn("Failed to fetch apps:", error);
				throw new Error("Service temporarily unavailable");
			}
		}
	}

	// Filter apps by search query if provided
	let filteredApps = allApps;
	if (query && query.trim() !== "") {
		const searchTerm = query.toLowerCase().trim();
		filteredApps = allApps.filter((app) => {
			// Search in app slug
			if (app.name_slug.toLowerCase().includes(searchTerm)) return true;

			// Search in display name
			if (app.name && app.name.toLowerCase().includes(searchTerm)) return true;

			// Search in description
			if (app.description && app.description.toLowerCase().includes(searchTerm))
				return true;

			// Search in categories
			if (
				app.categories &&
				app.categories.some((cat) => cat.toLowerCase().includes(searchTerm))
			)
				return true;

			// Search in allowed domains (for user convenience)
			if (app.allowed_domains.some((domain) => domain.includes(searchTerm)))
				return true;

			return false;
		});
	}

	// Sort by relevance (exact matches first, then alphabetical)
	if (query) {
		filteredApps.sort((a, b) => {
			const queryLower = query.toLowerCase();
			const aExact = a.name_slug.toLowerCase() === queryLower;
			const bExact = b.name_slug.toLowerCase() === queryLower;
			if (aExact && !bExact) return -1;
			if (!aExact && bExact) return 1;
			return (a.name || a.name_slug).localeCompare(b.name || b.name_slug);
		});
	}

	// Apply limit
	return filteredApps.slice(0, limit);
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
type SystemAppAuth =
	| {
			type: "api_key_header";
			header: string;
			valueEnv: string; // Name of Env field holding the secret
	  }
	| {
			type: "session_cookie";
			// Cookie authentication handled by DickerDataAuth class
	  };

interface SystemAppConfigEntry {
	appSlug: string;
	allowedDomains: string[]; // hostnames allowed for absolute URLs
	baseUrl: string; // base origin for relative paths (e.g., https://api.example.com/v1)
	auth: SystemAppAuth;
	defaultHeaders?: Record<string, string>;
}

type SystemAppsConfig = SystemAppConfigEntry[];

// Shared API monitoring utilities
interface APIMonitoringContext {
	method: string;
	url: string;
	app: string;
	latency: number;
	status: number;
	requestSize: number;
	responseSize: number;
	headersCount: number;
	userId?: string;
	userEmail?: string;
	accountId?: string;
	authType?: string;
	requestPreview?: string;
	responsePreview?: string;
	host?: string;
}

function logAPIRequest(
	method: string,
	url: string,
	app: string,
	requestSize: number,
	headersCount: number,
	userContext?: string,
): void {
	const userInfo = userContext ? ` [${userContext}]` : "";
	console.log(`🚀 API Request: ${method} ${url} [App: ${app}]${userInfo}`);
	console.log(
		`📊 Request size: ${requestSize} bytes, Headers: ${headersCount}`,
	);
}

function logAPIResponse(
	status: number,
	latency: number,
	responseSize: number,
	app: string,
): void {
	console.log(
		`✅ API Response: ${status} [${latency}ms, ${responseSize} bytes, App: ${app}]`,
	);
}

function createAPIBreadcrumb(
	context: APIMonitoringContext,
	category: "mcp.proxy.response" | "mcp.system.response",
): void {
	try {
		if (typeof Sentry !== "undefined") {
			const success = context.status >= 200 && context.status < 400;
			const performanceTier =
				context.latency < 500
					? "fast"
					: context.latency < 2000
						? "medium"
						: "slow";

			Sentry.addBreadcrumb({
				category,
				level:
					context.status >= 500
						? "error"
						: context.status >= 400
							? "warning"
							: "info",
				data: {
					// Response metrics
					status: context.status,
					latency_ms: context.latency,
					success,
					response_size_bytes: context.responseSize,

					// Request context
					method: context.method,
					app: context.app,
					...(context.userId && { user_id: context.userId }),
					...(context.userEmail && { user_email: context.userEmail }),
					...(context.accountId && { account_id: context.accountId }),

					// Request details
					request_size_bytes: context.requestSize,
					headers_count: context.headersCount,

					// Target info
					...(context.host && { host: context.host }),

					// Performance categorization
					performance_tier: performanceTier,

					// Auth context for system requests
					...(context.authType && { auth_type: context.authType }),

					// Sanitized request/response preview
					...(context.requestPreview && {
						request_preview: context.requestPreview,
					}),
					...(context.responsePreview && {
						response_preview: context.responsePreview,
					}),
				},
			});

			// For slow requests or errors, also capture as Sentry events for visibility
			if (context.latency > 3000 || context.status >= 400) {
				const eventLevel =
					context.status >= 500
						? "error"
						: context.status >= 400
							? "warning"
							: "info";
				const requestType =
					category === "mcp.system.response" ? "System API" : "API";
				Sentry.captureMessage(
					`${requestType} ${success ? "Performance" : "Error"}: ${context.method} ${context.app} - ${context.status} in ${context.latency}ms`,
					eventLevel,
				);
			}
		}
	} catch (e) {
		// Silent fallback for Sentry operations
	}
}

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

	const dickerData: SystemAppConfigEntry = {
		appSlug: "dicker_data",
		allowedDomains: ["portal.dickerdata.co.nz"],
		baseUrl: "https://portal.dickerdata.co.nz",
		auth: {
			type: "session_cookie",
		},
		defaultHeaders: {
			Accept: "application/json, text/plain, */*",
			"Content-Type": "application/json",
		},
	};

	return [gamma, dickerData];
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
		tenant?: string;
		user?: string;
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
		case "session_cookie": {
			if (params.app.appSlug === "dicker_data") {
				try {
					const dickerAuth = new DickerDataAuth(
						env,
						params.tenant,
						params.user,
					);
					const cookieString = await dickerAuth.refreshSessionIfNeeded();
					headers["Cookie"] = cookieString;

					// Add additional headers that Dicker Data expects
					headers["User-Agent"] =
						"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36";
					headers["X-Requested-With"] = "XMLHttpRequest";
					headers["Referer"] = "https://portal.dickerdata.co.nz/";

					// Override default Accept header with Dicker Data specific format
					if (!headers["Accept"] || headers["Accept"] === "application/json") {
						headers["Accept"] = "application/json, text/plain, */*";
					}
				} catch (error) {
					console.error("Dicker Data authentication failed:", error);
					return {
						status: 500,
						data: {
							error: "dicker_data_auth_failed",
							message: `Failed to authenticate with Dicker Data: ${error instanceof Error ? error.message : "Unknown error"}`,
							app: params.app.appSlug,
						},
					};
				}
			}
			break;
		}
	}

	if (!headers["Accept"]) headers["Accept"] = "application/json";
	if (params.app.defaultHeaders)
		Object.assign(headers, params.app.defaultHeaders);

	// Body handling
	let bodyToSend: BodyInit | null = null;
	if (params.body !== undefined) {
		// Transform payload for Dicker Data API compatibility
		let processedBody = params.body;
		if (
			params.app.appSlug === "dicker_data" &&
			typeof params.body === "object" &&
			params.body !== null
		) {
			const body = params.body as Record<string, any>;

			// Transform user-friendly searchTerm to Dicker Data API format
			if ("searchTerm" in body) {
				processedBody = {
					searchKeyword: body.searchTerm,
					brand: body.brand || "",
					type: body.type || "",
					category: body.category || "",
					series: body.series || "",
					minPrice: body.minPrice ? String(body.minPrice) : "",
					maxPrice: body.maxPrice ? String(body.maxPrice) : "",
					excludeKits: body.excludeKits || false,
					minSOH: body.minSOH ? String(body.minSOH) : "",
				};
			}
		}

		if (typeof processedBody === "string") {
			bodyToSend = processedBody as string;
			if (!headers["Content-Type"]) headers["Content-Type"] = "text/plain";
		} else {
			bodyToSend = JSON.stringify(processedBody);
			if (!headers["Content-Type"])
				headers["Content-Type"] = "application/json";
		}
	}

	// Execute request with retry logic for session cookie auth
	const executeRequest = async (
		requestHeaders: Record<string, string>,
	): Promise<{ status: number; data: any }> => {
		const startTime = Date.now();
		const requestSize = bodyToSend
			? typeof bodyToSend === "string"
				? bodyToSend.length
				: JSON.stringify(bodyToSend).length
			: 0;
		const headersCount = Object.keys(requestHeaders).length;

		// Log request using shared utility
		logAPIRequest(
			params.method,
			finalUrl,
			params.app.appSlug,
			requestSize,
			headersCount,
		);

		const resp = await fetch(finalUrl, {
			method: params.method,
			headers: requestHeaders,
			body: bodyToSend,
		});

		const endTime = Date.now();
		const latency = endTime - startTime;

		const text = await resp.text();
		let data: any;
		try {
			data = JSON.parse(text);
		} catch {
			data = text;
		}

		const responseSize = text.length;

		// Log response using shared utility
		logAPIResponse(resp.status, latency, responseSize, params.app.appSlug);

		// Create breadcrumb using shared utility
		createAPIBreadcrumb(
			{
				method: params.method,
				url: finalUrl,
				app: params.app.appSlug,
				latency,
				status: resp.status,
				requestSize,
				responseSize,
				headersCount,
				authType: params.app.auth.type,
				host: new URL(finalUrl).hostname,
				requestPreview: bodyToSend
					? (typeof bodyToSend === "string"
							? bodyToSend
							: JSON.stringify(bodyToSend)
						).substring(0, 200) + (requestSize > 200 ? "..." : "")
					: undefined,
				responsePreview:
					text.substring(0, 200) + (responseSize > 200 ? "..." : ""),
			},
			"mcp.system.response",
		);

		return { status: resp.status, data };
	};

	// First attempt
	let result = await executeRequest(headers);

	// Retry logic for session cookie authentication failures
	if (
		params.app.auth.type === "session_cookie" &&
		params.app.appSlug === "dicker_data" &&
		(result.status === 401 ||
			result.status === 403 ||
			(result.status === 302 &&
				typeof result.data === "string" &&
				result.data.includes("Login")))
	) {
		console.log(
			"🔄 Dicker Data session appears expired, attempting fresh authentication",
		);

		try {
			// Force a fresh login
			const dickerAuth = new DickerDataAuth(env, params.tenant, params.user);
			const freshCookieString = await dickerAuth.getValidSession();

			// Update headers with fresh cookies
			const freshHeaders = { ...headers };
			freshHeaders["Cookie"] = freshCookieString;

			// Retry the request
			console.log("🔄 Retrying request with fresh Dicker Data session");
			result = await executeRequest(freshHeaders);
		} catch (retryError) {
			console.error(
				"Failed to retry with fresh Dicker Data session:",
				retryError,
			);
			return {
				status: 500,
				data: {
					error: "dicker_data_retry_failed",
					message: `Authentication retry failed: ${retryError instanceof Error ? retryError.message : "Unknown error"}`,
					original_status: result.status,
				},
			};
		}
	}

	return result;
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
	if (!res.ok) {
		console.warn(`Pipedream token error ${res.status}`);
		throw new Error("Authentication service unavailable");
	}
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

// (removed) Xero tenant helper; asi_magic_tool path is now canonical

// ---- URL Access Policy (KV-backed) ----

type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
type Provider = "system" | "pipedream";

interface PolicyRule {
	id?: string;
	description?: string;
	effect: "allow" | "deny";
	subjects?: {
		users?: string[]; // exact match on sub or email
		groups?: string[]; // Cloudflare Access / IdP groups
	};
	providers?: (Provider | "*")[];
	apps?: string[]; // e.g., ["hubspot", "gamma", "dicker_data"] or ["*"]
	methods?: (HttpMethod | "*")[];
	hosts?: string[]; // wildcards supported, e.g., ["api.example.com", "*.corp.local"]
	paths?: string[]; // wildcards supported, e.g., ["/v1/**", "/orders/*/lines"]
}

interface PolicyDocument {
	version: string; // e.g., "2025-08-01"
	defaultMode: "allow" | "deny"; // global default
	appDefaults?: Record<string, "allow" | "deny">; // per-app default (overrides global)
	rules: PolicyRule[];
}

// Optional: in-memory cache
let IN_MEMORY_POLICY: { expiresAt: number; data: PolicyDocument } | undefined;

// Basic wildcard matcher: "*", "**" and "?" supported
// Protected against ReDoS with input length limits and simplified patterns
function wildcardToRegExp(input: string): RegExp {
	// Prevent ReDoS attacks with input length limit
	if (input.length > 200) {
		throw new Error("Pattern too long for security");
	}

	// Validate input contains only safe characters
	if (!/^[a-zA-Z0-9.\-_/*?]+$/.test(input)) {
		throw new Error("Pattern contains unsafe characters");
	}

	// Escape regex metachars, avoiding catastrophic backtracking
	let escaped = "";
	for (let i = 0; i < input.length; i++) {
		const char = input[i];
		switch (char) {
			case "*":
				if (input[i + 1] === "*") {
					escaped += ".*?"; // Non-greedy matching to prevent backtracking
					i++; // Skip next *
				} else {
					escaped += "[^/]*?"; // Non-greedy matching
				}
				break;
			case "?":
				escaped += ".";
				break;
			case ".":
			case "-":
			case "[":
			case "]":
			case "(":
			case ")":
			case "^":
			case "$":
			case "+":
			case "{":
			case "}":
			case "|":
			case "\\":
				escaped += "\\" + char;
				break;
			default:
				escaped += char;
		}
	}
	return new RegExp("^" + escaped + "$");
}

function matchOne(target: string | undefined, patterns?: string[]): boolean {
	if (!patterns || patterns.length === 0) return true; // unspecified -> matches all
	if (!target) return false;
	return patterns.some((p) => {
		try {
			return wildcardToRegExp(p).test(target);
		} catch {
			// If pattern is invalid, treat as non-matching for security
			return false;
		}
	});
}

function matchSet<T extends string>(
	target: T | undefined,
	set?: (T | "*")[],
): boolean {
	if (!set || set.length === 0) return true;
	if (!target) return false;
	return set.includes("*" as any) || set.includes(target);
}

function normalizePath(p?: string): string | undefined {
	if (!p) return p;
	return p.startsWith("/") ? p : "/" + p;
}

function getIdentityFromProps(props: unknown): {
	sub?: string;
	email?: string;
	groups: string[];
} {
	const anyProps = (props || {}) as any;
	const sub = anyProps?.sub as string | undefined;
	const email = anyProps?.email as string | undefined;

	// Try common locations/names for groups claims.
	const groupsCandidates: unknown[] = [
		anyProps?.groups,
		anyProps?.roles,
		anyProps?.entitlements,
		anyProps?.["https://cloudflareaccess.com/claims/groups"],
	];
	const groups: string[] =
		(groupsCandidates.find((g) => Array.isArray(g)) as string[] | undefined) ||
		[];

	return { sub, email, groups };
}

async function loadPolicy(env: Env): Promise<PolicyDocument> {
	const now = Date.now();
	if (IN_MEMORY_POLICY && IN_MEMORY_POLICY.expiresAt > now) {
		return IN_MEMORY_POLICY.data;
	}
	let raw: string | null = null;
	try {
		// Global security policy - intentionally not tenant-scoped
		// All tenants share the same security controls and access patterns
		raw = await env.USER_LINKS.get("mcp:policy:v1");
	} catch {}
	let policy: PolicyDocument;

	if (raw) {
		try {
			policy = JSON.parse(raw) as PolicyDocument;
		} catch {
			// corrupt KV -> safe default
			policy = { version: "default", defaultMode: "deny", rules: [] };
		}
	} else {
		// default if not configured yet (least privilege)
		policy = { version: "default", defaultMode: "deny", rules: [] };
	}

	IN_MEMORY_POLICY = { expiresAt: now + 60_000, data: policy }; // 60s cache
	return policy;
}

// Evaluate request against policy
async function evaluatePolicy(
	env: Env,
	input: {
		sub?: string;
		email?: string;
		groups: string[];
		provider: Provider;
		app?: string;
		method: HttpMethod;
		host?: string;
		path?: string;
		fullUrl?: string;
	},
): Promise<{
	allow: boolean;
	matchedRule?: PolicyRule & { index?: number };
	decision: "allow" | "deny" | "default";
	reason?: string;
}> {
	const policy = await loadPolicy(env);
	const { sub, email, groups, provider, app, method, host, path } = input;

	// Helper: does this rule apply to the subject?
	const subjectMatches = (r: PolicyRule): boolean => {
		const s = r.subjects;
		if (!s) return true;
		const users = s.users || [];
		const groupsRule = s.groups || [];
		const userIdMatches =
			users.length === 0 ||
			users.includes(sub || "") ||
			users.includes(email || "");
		const groupMatches =
			groupsRule.length === 0 || groupsRule.some((g) => groups.includes(g));
		return userIdMatches && groupMatches;
	};

	// Compute app default (if present)
	const appDefault =
		(app && policy.appDefaults && policy.appDefaults[app]) || undefined;

	// Collect matching rules (provider/app/method/host/path AND subject)
	const pathNorm = normalizePath(path);
	const matches = (r: PolicyRule) =>
		subjectMatches(r) &&
		matchSet(provider, r.providers as any) &&
		matchOne(app, r.apps) &&
		matchSet(method, r.methods as any) &&
		matchOne(host, r.hosts) &&
		matchOne(pathNorm, r.paths);

	const matched = policy.rules
		.map((r, i) => ({ r, i }))
		.filter(({ r }) => matches(r));

	// Deny overrides allow
	const deny = matched.find(({ r }) => r.effect === "deny");
	if (deny) {
		return {
			allow: false,
			matchedRule: { ...deny.r, index: deny.i },
			decision: "deny",
			reason: "Matched explicit deny rule",
		};
	}
	const allow = matched.find(({ r }) => r.effect === "allow");
	if (allow) {
		return {
			allow: true,
			matchedRule: { ...allow.r, index: allow.i },
			decision: "allow",
			reason: "Matched explicit allow rule",
		};
	}

	// Fall back to per-app default, then global default
	const fallback: "allow" | "deny" = appDefault || policy.defaultMode;
	return {
		allow: fallback === "allow",
		decision: "default",
		reason:
			fallback === "allow"
				? "No matching rule; allowed by default policy"
				: "No matching rule; denied by default policy",
	};
}

// ---- MCP Server class ----
export class ASIConnectMCP extends McpAgent<Env, unknown, Props> {
	server = new McpServer({ name: "ASI Connect MCP", version: "1.0.0" });

	// Helper to derive a stable user id for Pipedream Connect from OAuth claims
	private getExternalUserId() {
		const sub = this.props?.sub;
		const tenant = (this.props as any)?.tenant_id || "default";
		if (!sub) {
			throw new Error("Authentication required");
		}
		return `${tenant}:${sub}`;
	}

	// Helper to generate tenant-scoped KV keys
	private getTenantKey(key: string, scoped: boolean = true): string {
		if (!scoped) return key; // Global keys like cache remain unscoped
		const tenant = (this.props as any)?.tenant_id || "default";
		const sub = this.props?.sub || "unknown";
		return `tenant:${tenant}:user:${sub}:${key}`;
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
				Sentry.setTag("tenant", (this.props as any)?.tenant_id || "default");
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
											text: JSON.stringify({
												error: "internal_error",
												eventId,
											}),
										},
									],
								};
							}
						},
					);
				} catch (sentryError) {
					console.warn(
						`Sentry span creation failed, falling back to direct execution:`,
						sentryError,
					);
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
							text: JSON.stringify({
								error: "internal_error",
								eventId: "sentry_unavailable",
							}),
						},
					],
				};
			}
		};
	}

	async init() {
		// -------- assistant_instructions prompt --------
		this.server.prompt(
			"assistant_instructions",
			"Get instructions for the AI assistant on how to help users with their tasks",
			async () => {
				const external_user_id = this.getExternalUserId();
				const pdToken = await getPdAccessToken(this.env);

				// Get currently connected apps for this user
				const res = await listAccountsForUser(
					this.env,
					pdToken,
					external_user_id,
					undefined,
					false,
				);

				const connectedApps = (res.data || []).map((a) => ({
					app: a.app?.name_slug,
					account_id: a.id,
					healthy: a.healthy,
					dead: a.dead,
				}));

				const instructions = `
## Assistant Instructions

If the user asks you to perform a task, search for the relevant SOP and follow it. The SOP will contain the required apps and HTTP requests to make with the asi_magic_tool.

If the user needs to connect to an app, use the app slug from the SOP. If it's not in the SOP, you can search for the app with the search_apps tool.

## Currently Connected Apps

${
	connectedApps.length > 0
		? connectedApps
				.map(
					(app) =>
						`- **${app.app}** (${app.healthy ? "healthy" : app.dead ? "dead" : "unknown status"}) - Account ID: ${app.account_id}`,
				)
				.join("\n")
		: "- No apps currently connected"
}

## Key Steps for Task Execution

1. **Search for relevant SOPs** using the \`search_sop_docs\` tool
2. **Follow the SOP process** - it contains the required apps and API calls
3. **Connect to required apps** if not already connected using \`auth_connect\` with the app slug from the SOP
4. **Make API requests** using the \`asi_magic_tool\` as specified in the SOP
5. **Handle any authentication** - if a request fails with auth required, use the connect URL provided

## Available Tools
- \`search_sop_docs\` - Search ASI Solutions documentation for processes
- \`get_sop_process\` - Get specific SOP by process code (e.g., FIN-001)
- \`search_apps\` - Find available apps to connect to
- \`auth_connect\` - Generate connection links for apps
- \`auth_status\` - Check current connection status
- \`asi_magic_tool\` - Make authenticated API requests
- \`update_docs\` - Create or update documentation files with pull request creation
- \`send_feedback\` - Report issues or request new features
`;

				return {
					messages: [
						{
							role: "assistant",
							content: {
								type: "text",
								text: instructions.trim(),
							},
						},
					],
				};
			},
		);

		// -------- assistant_instructions resource --------
		this.server.resource(
			"assistant_instructions",
			"Get assistant instructions as a resource",
			async () => {
				const external_user_id = this.getExternalUserId();
				const pdToken = await getPdAccessToken(this.env);

				// Get currently connected apps for this user
				const res = await listAccountsForUser(
					this.env,
					pdToken,
					external_user_id,
					undefined,
					false,
				);

				const connectedApps = (res.data || []).map((a) => ({
					app: a.app?.name_slug,
					account_id: a.id,
					healthy: a.healthy,
					dead: a.dead,
				}));

				const instructions = `
## Assistant Instructions

If the user asks you to perform a task, search for the relevant SOP and follow it. The SOP will contain the required apps and HTTP requests to make with the asi_magic_tool.

If the user needs to connect to an app, use the app slug from the SOP. If it's not in the SOP, you can search for the app with the search_apps tool.

## Currently Connected Apps

${
	connectedApps.length > 0
		? connectedApps
				.map(
					(app) =>
						`- **${app.app}** (${app.healthy ? "healthy" : app.dead ? "dead" : "unknown status"}) - Account ID: ${app.account_id}`,
				)
				.join("\n")
		: "- No apps currently connected"
}

## Key Steps for Task Execution

1. **Search for relevant SOPs** using the \`search_sop_docs\` tool
2. **Follow the SOP process** - it contains the required apps and API calls
3. **Connect to required apps** if not already connected using \`auth_connect\` with the app slug from the SOP
4. **Make API requests** using the \`asi_magic_tool\` as specified in the SOP
5. **Handle any authentication** - if a request fails with auth required, use the connect URL provided

## Available Tools
- \`search_sop_docs\` - Search ASI Solutions documentation for processes
- \`get_sop_process\` - Get specific SOP by process code (e.g., FIN-001)
- \`search_apps\` - Find available apps to connect to
- \`auth_connect\` - Generate connection links for apps
- \`auth_status\` - Check current connection status
- \`asi_magic_tool\` - Make authenticated API requests
- \`update_docs\` - Create or update documentation files with pull request creation
- \`send_feedback\` - Report issues or request new features
`;

				return {
					contents: [
						{
							uri: "mcp://assistant_instructions/instructions.md",
							mimeType: "text/markdown",
							text: instructions.trim(),
						},
					],
				};
			},
		);

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
						await this.env.USER_LINKS.delete(this.getTenantKey("xero-tenant"));
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

		// -------- search_apps --------
		this.server.tool(
			"search_apps",
			{
				query: z.string().min(1).max(200).optional(),
				name: z.string().min(1).max(100).optional(),
				slug: z.string().min(1).max(100).optional(),
				description: z.string().min(1).max(200).optional(),
				domain: z.string().min(1).max(100).optional(),
				limit: z.number().min(1).max(50).optional(),
			},
			this.withSentryInstrumentation(
				"search_apps",
				() => undefined, // no single app
				async ({
					query,
					name,
					slug,
					description,
					domain,
					limit = 10,
				}: {
					query?: string;
					name?: string;
					slug?: string;
					description?: string;
					domain?: string;
					limit?: number;
				}) => {
					const pdToken = await getPdAccessToken(this.env);

					// Build URL with query parameters per Pipedream API docs
					let url = "https://api.pipedream.com/v1/apps";
					const params = new URLSearchParams();

					// Use the 'q' parameter for general search as per API docs
					if (query) {
						params.set("q", query);
					}

					if (params.toString()) {
						url += "?" + params.toString();
					}

					// Fetch apps from Pipedream with query parameters
					// Note: x-pd-environment header causes "record not found" - remove it for global app search
					const res = await fetch(url, {
						headers: {
							Authorization: `Bearer ${pdToken}`,
						},
					});
					if (!res.ok)
						throw new Error(`Pipedream apps search error ${res.status}`);
					const body = (await res.json()) as { data?: PdAppInfo[] };
					const allApps = body.data || [];

					// Apply additional client-side filters for parameters not supported by API
					let filteredApps = allApps;
					if (name) {
						const nameLower = name.toLowerCase();
						filteredApps = filteredApps.filter((app) =>
							app.name?.toLowerCase().includes(nameLower),
						);
					}

					if (slug) {
						const slugLower = slug.toLowerCase();
						filteredApps = filteredApps.filter((app) =>
							app.name_slug?.toLowerCase().includes(slugLower),
						);
					}

					if (description) {
						const descLower = description.toLowerCase();
						filteredApps = filteredApps.filter((app) =>
							app.description?.toLowerCase().includes(descLower),
						);
					}

					if (domain) {
						const domainLower = domain.toLowerCase();
						filteredApps = filteredApps.filter((app) =>
							app.connect?.allowed_domains?.some((d) =>
								d.toLowerCase().includes(domainLower),
							),
						);
					}

					// Sort by relevance (exact matches first, then alphabetical)
					filteredApps.sort((a, b) => {
						if (query) {
							const aExact = a.name_slug.toLowerCase() === query.toLowerCase();
							const bExact = b.name_slug.toLowerCase() === query.toLowerCase();
							if (aExact && !bExact) return -1;
							if (!aExact && bExact) return 1;
						}
						return (a.name || a.name_slug).localeCompare(b.name || b.name_slug);
					});

					// Apply limit
					const results = filteredApps.slice(0, limit);

					// Format results for response
					const formattedResults = results.map((app) => ({
						name_slug: app.name_slug,
						name: app.name,
						description: app.description,
						connect_enabled: !!app.connect?.proxy_enabled,
						allowed_domains: app.connect?.allowed_domains || [],
						base_url: app.connect?.base_proxy_target_url,
						is_dynamic: /\{\{[^}]+\}\}/.test(
							app.connect?.base_proxy_target_url || "",
						),
					}));

					return {
						content: [
							{
								type: "text",
								text: JSON.stringify({
									query,
									filters: { name, slug, description, domain },
									results: formattedResults,
									total_results: formattedResults.length,
									total_available: allApps.length,
									environment: this.env.PIPEDREAM_ENV,
								}),
							},
						],
					};
				},
			),
		);

		// (removed) http_request tool

		// -------- ASI Magic Tool (formerly proxy_request) --------
		this.server.tool(
			"asi_magic_tool",
			{
				method: z
					.enum(["GET", "POST", "PUT", "PATCH", "DELETE"])
					.describe("HTTP method for the API request"),
				url: z
					.string()
					.describe(
						"API endpoint URL. CRITICAL: Before using this tool, ALWAYS search for and review relevant SOPs using search_sop_docs to ensure you follow proper procedures and understand the correct API usage patterns.",
					),
				headers: z
					.record(z.string())
					.optional()
					.describe("Custom HTTP headers for the request"),
				body: z
					.union([z.string(), z.record(z.any())])
					.optional()
					.describe("Request body data (JSON object or string)"),
				account_id: z
					.string()
					.optional()
					.describe("Specific account ID to use for authentication"),
				app: z
					.string()
					.optional()
					.describe("App slug to use (e.g., 'xero_accounting_api', 'hubspot')"),
				provider: z
					.enum(["system", "pipedream"])
					.optional()
					.describe("Force specific provider (system or pipedream)"),
			},
			this.withSentryInstrumentation(
				"asi_magic_tool",
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

						// Get identity once
						const { sub, email, groups } = getIdentityFromProps(this.props);

						// Build final URL (absolute) for policy evaluation
						let policyUrl = url;
						try {
							policyUrl = buildSystemUrl(url, selectedSystemApp);
						} catch {}
						let host: string | undefined, pathOnly: string | undefined;
						try {
							const u = new URL(policyUrl);
							host = u.hostname;
							pathOnly = u.pathname;
						} catch {}

						const decision = await evaluatePolicy(this.env, {
							sub,
							email,
							groups,
							provider: "system",
							app: selectedSystemApp.appSlug,
							method,
							host,
							path: pathOnly,
							fullUrl: policyUrl,
						});

						if (!decision.allow) {
							return {
								content: [
									{
										type: "text",
										text: JSON.stringify({
											error: "blocked_by_policy",
											message: "This request was blocked by policy.",
											reason: decision.reason,
											matched_rule: decision.matchedRule,
											context: {
												provider: "system",
												app: selectedSystemApp.appSlug,
												method,
												host,
												path: pathOnly,
											},
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
							tenant: (this.props as any)?.tenant_id,
							user: this.props?.sub,
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
						// Get identity once
						const { sub, email, groups } = getIdentityFromProps(this.props);

						// Build final URL (absolute) for policy evaluation
						let policyUrl = url;
						try {
							policyUrl = buildSystemUrl(url, selectedSystemApp);
						} catch {}
						let host: string | undefined, pathOnly: string | undefined;
						try {
							const u = new URL(policyUrl);
							host = u.hostname;
							pathOnly = u.pathname;
						} catch {}

						const decision = await evaluatePolicy(this.env, {
							sub,
							email,
							groups,
							provider: "system",
							app: selectedSystemApp.appSlug,
							method,
							host,
							path: pathOnly,
							fullUrl: policyUrl,
						});

						if (!decision.allow) {
							return {
								content: [
									{
										type: "text",
										text: JSON.stringify({
											error: "blocked_by_policy",
											message: "This request was blocked by policy.",
											reason: decision.reason,
											matched_rule: decision.matchedRule,
											context: {
												provider: "system",
												app: selectedSystemApp.appSlug,
												method,
												host,
												path: pathOnly,
											},
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
							tenant: (this.props as any)?.tenant_id,
							user: this.props?.sub,
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

					// Process headers for Pipedream Connect proxy
					// Pipedream Connect proxy only forwards headers with x-pd-proxy- prefix
					let processedHeaders: Record<string, string> | undefined;
					if (headers) {
						processedHeaders = {};
						for (const [key, value] of Object.entries(headers)) {
							// Add x-pd-proxy- prefix to all custom headers so they get forwarded
							if (!key.toLowerCase().startsWith("x-pd-proxy-")) {
								processedHeaders[`x-pd-proxy-${key}`] = value;
							} else {
								// Already has prefix, keep as-is
								processedHeaders[key] = value;
							}
						}
					}

					// Get identity once
					const { sub, email, groups } = getIdentityFromProps(this.props);

					// Resolve host/path for policy. If URL is relative (dynamic app), host may be unknown.
					const isFullUrlNow = /^https?:\/\//i.test(url);
					let host: string | undefined, pathOnly: string | undefined;
					if (isFullUrlNow) {
						try {
							const u = new URL(url);
							host = u.hostname;
							pathOnly = u.pathname;
						} catch {}
					} else {
						// relative path; rely on path-only policy for dynamic apps
						pathOnly = url.startsWith("/") ? url : "/" + url;
					}

					const decision = await evaluatePolicy(this.env, {
						sub,
						email,
						groups,
						provider: "pipedream",
						app: resolvedApp!,
						method,
						host,
						path: pathOnly,
						fullUrl: url,
					});

					if (!decision.allow) {
						return {
							content: [
								{
									type: "text",
									text: JSON.stringify({
										error: "blocked_by_policy",
										message: "This request was blocked by policy.",
										reason: decision.reason,
										matched_rule: decision.matchedRule,
										context: {
											provider: "pipedream",
											app: resolvedApp,
											method,
											host,
											path: pathOnly,
										},
									}),
								},
							],
						};
					}

					// Add nested span for the actual HTTP request (with fallback)
					let result: any;
					const executeProxyRequest = async () => {
						const startTime = Date.now();
						const userId = this.getExternalUserId();
						const userEmail = this.props?.email as string | undefined;

						// Calculate request details
						const requestSize = proxyBody
							? JSON.stringify(proxyBody).length
							: 0;
						const headersCount = processedHeaders
							? Object.keys(processedHeaders).length
							: 0;

						// Log request using shared utility
						const userContext = `App: ${resolvedApp}, User: ${userEmail || userId}`;
						logAPIRequest(
							method,
							url,
							resolvedApp,
							requestSize,
							headersCount,
							userContext,
						);

						const resp = await proxyRequest(this.env, pdToken!, {
							external_user_id,
							account_id: acctId,
							method,
							url,
							headers: processedHeaders,
							body: proxyBody,
						});

						const endTime = Date.now();
						const latency = endTime - startTime;

						// Calculate response details
						const responseSize = resp.data
							? JSON.stringify(resp.data).length
							: 0;

						// Log response using shared utility
						logAPIResponse(resp.status, latency, responseSize, resolvedApp);

						// Create breadcrumb using shared utility
						createAPIBreadcrumb(
							{
								method,
								url,
								app: resolvedApp,
								latency,
								status: resp.status,
								requestSize,
								responseSize,
								headersCount,
								userId,
								userEmail,
								accountId: acctId,
								host: isFullUrl ? new URL(url).hostname : "api.pipedream.com",
								requestPreview: proxyBody
									? JSON.stringify(proxyBody).substring(0, 200) +
										(requestSize > 200 ? "..." : "")
									: undefined,
								responsePreview: resp.data
									? JSON.stringify(resp.data).substring(0, 200) +
										(responseSize > 200 ? "..." : "")
									: undefined,
							},
							"mcp.proxy.response",
						);

						return resp;
					};

					if (this.env.SENTRY_DSN) {
						try {
							result = await Sentry.startSpan(
								{
									name: `mcp.proxy.${resolvedApp}.${method}`,
									op: "http.client",
									attributes: {
										// Standard HTTP attributes
										"http.method": method,
										"http.url": new URL(url, "https://example.com").origin, // avoid path params in spans
										"dest.host": isFullUrl
											? new URL(url).hostname
											: "api.pipedream.com",

										// MCP context
										"mcp.app": resolvedApp ?? "unknown",
										"mcp.user.sub": external_user_id,
										"mcp.user.email":
											(this.props?.email as string) || "unknown",
										"mcp.account_id": acctId || "unknown",

										// Request metadata
										"mcp.request.size_bytes": proxyBody
											? JSON.stringify(proxyBody).length
											: 0,
										"mcp.request.headers_count": processedHeaders
											? Object.keys(processedHeaders).length
											: 0,
										"mcp.request.has_body": !!proxyBody,
									},
								},
								async (span) => {
									const spanStartTime = Date.now();
									const result = await executeProxyRequest();
									const spanLatency = Date.now() - spanStartTime;

									// Add result attributes to span after execution
									if (span) {
										try {
											span.setAttributes({
												"http.status_code": result.status,
												"mcp.response.success":
													result.status >= 200 && result.status < 400,
												"mcp.response.size_bytes": result.data
													? JSON.stringify(result.data).length
													: 0,
												"mcp.span.latency_ms": spanLatency,
												"mcp.latency_category":
													spanLatency < 500
														? "fast"
														: spanLatency < 2000
															? "medium"
															: "slow",
											});
										} catch (e) {
											// Silent fallback for span attribute setting
										}
									}

									return result;
								},
							);
						} catch (sentryError) {
							console.warn(
								`Sentry HTTP span failed, falling back to direct execution:`,
								sentryError,
							);
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

		// -------- search_sop_docs --------
		this.server.tool(
			"search_sop_docs",
			{
				query: z
					.string()
					.min(1)
					.max(200)
					.describe(
						"Search query for SOP documentation. CRITICAL: Always search for and review relevant SOPs before using the ASI Magic Tool (asi_magic_tool) to ensure proper procedures are followed.",
					),
				search_type: z
					.enum([
						"process",
						"quick",
						"system",
						"sales",
						"finance",
						"operations",
						"support",
					])
					.optional()
					.describe("Type of SOP to search for"),
				system: z
					.string()
					.optional()
					.describe(
						"Specific system name to search SOPs for (e.g., 'xero', 'hubspot')",
					),
				limit: z
					.number()
					.min(1)
					.max(20)
					.optional()
					.describe("Maximum number of results to return"),
				include_content: z
					.boolean()
					.optional()
					.describe("Whether to include full SOP content in results"),
			},
			this.withSentryInstrumentation(
				"search_sop_docs",
				() => undefined, // no single app
				async ({
					query,
					search_type,
					system,
					limit,
					include_content,
				}: {
					query: string;
					search_type?:
						| "process"
						| "quick"
						| "system"
						| "sales"
						| "finance"
						| "operations"
						| "support";
					system?: string;
					limit?: number;
					include_content?: boolean;
				}) => {
					console.log(`🔍 SOP search called with:`, {
						query,
						search_type,
						system,
						limit,
						include_content,
					});

					const token = this.env.GITHUB_TOKEN;
					console.log(`🔑 GitHub token present: ${!!token}`);

					if (!token) {
						console.error("❌ GitHub token missing");
						return {
							content: [
								{
									type: "text",
									text: JSON.stringify({
										error: "github_not_configured",
										message:
											"GitHub token not configured for SOP documentation search",
									}),
								},
							],
						};
					}

					const sopOwner = this.env.GITHUB_SOP_OWNER || "ASISolutions";
					const sopRepo = this.env.GITHUB_SOP_REPO || "docs";
					const sopBranch = this.env.GITHUB_SOP_BRANCH || "main";

					console.log(
						`📚 Using repository: ${sopOwner}/${sopRepo} (branch: ${sopBranch})`,
					);

					try {
						const sopService = new SOPSearchService(
							token,
							sopOwner,
							sopRepo,
							sopBranch,
						);
						console.log(`🚀 Starting search...`);
						const results = await sopService.search(query, {
							searchType: search_type,
							system,
							limit: limit || 5,
							includeContent: include_content || false,
						});

						console.log(`✅ Search completed, found ${results.length} results`);

						if (results.length === 0) {
							return {
								content: [
									{
										type: "text",
										text: JSON.stringify({
											query,
											results: [],
											total_results: 0,
											message:
												"No matching SOP documents found. Try different search terms or check if the repository exists.",
										}),
									},
								],
							};
						}

						// Format results for response
						const formattedResults = results.map((result) => ({
							path: result.path,
							process_code: result.metadata.process_code,
							title: result.metadata.title,
							description: result.metadata.description,
							category: result.metadata.category,
							systems: result.metadata.systems
								? Object.keys(result.metadata.systems)
								: undefined,
							estimated_time: result.metadata.estimated_time,
							requires_approval: result.metadata.requires_approval,
							owner: result.metadata.owner,
							last_modified: result.metadata.last_modified,
							...(include_content && { content: result.content }),
							gitbook_url: `https://asi-solutions.gitbook.io/docs/${result.path.replace(".md", "")}`,
						}));

						return {
							content: [
								{
									type: "text",
									text: JSON.stringify({
										query,
										search_type,
										system,
										results: formattedResults,
										total_results: formattedResults.length,
										repository: `${sopOwner}/${sopRepo}`,
									}),
								},
							],
						};
					} catch (error) {
						console.error(`💥 Search error:`, error);
						return {
							content: [
								{
									type: "text",
									text: JSON.stringify({
										error: "search_failed",
										message: `SOP documentation search failed: ${error instanceof Error ? error.message : "Unknown error"}`,
										query,
									}),
								},
							],
						};
					}
				},
			),
		);

		// -------- get_sop_process --------
		this.server.tool(
			"get_sop_process",
			{
				process_code: z
					.string()
					.regex(
						/^[A-Z]+-\d{3}$/,
						"Process code must be in format CATEGORY-001",
					),
			},
			this.withSentryInstrumentation(
				"get_sop_process",
				() => undefined,
				async ({ process_code }: { process_code: string }) => {
					console.log(`🎯 Process lookup called for: ${process_code}`);

					const token = this.env.GITHUB_TOKEN;
					if (!token) {
						console.error("❌ GitHub token missing for process lookup");
						return {
							content: [
								{
									type: "text",
									text: JSON.stringify({
										error: "github_not_configured",
										message:
											"GitHub token not configured for SOP documentation access",
									}),
								},
							],
						};
					}

					const sopOwner = this.env.GITHUB_SOP_OWNER || "ASISolutions";
					const sopRepo = this.env.GITHUB_SOP_REPO || "docs";
					const sopBranch = this.env.GITHUB_SOP_BRANCH || "main";

					try {
						const sopService = new SOPSearchService(
							token,
							sopOwner,
							sopRepo,
							sopBranch,
						);
						const result = await sopService.getByProcessCode(process_code);

						if (!result) {
							console.log(`❌ Process ${process_code} not found`);
							return {
								content: [
									{
										type: "text",
										text: JSON.stringify({
											error: "process_not_found",
											message: `Process ${process_code} not found in SOP documentation`,
											process_code,
										}),
									},
								],
							};
						}

						console.log(`✅ Process ${process_code} found at ${result.path}`);
						return {
							content: [
								{
									type: "text",
									text: JSON.stringify({
										process_code,
										path: result.path,
										metadata: result.metadata,
										content: result.content,
										gitbook_url: `https://asi-solutions.gitbook.io/docs/${result.path.replace(".md", "")}`,

										repository: `${sopOwner}/${sopRepo}`,
									}),
								},
							],
						};
					} catch (error) {
						console.error(`💥 Process lookup error:`, error);
						return {
							content: [
								{
									type: "text",
									text: JSON.stringify({
										error: "process_fetch_failed",
										message: `Failed to fetch process ${process_code}: ${error instanceof Error ? error.message : "Unknown error"}`,
										process_code,
									}),
								},
							],
						};
					}
				},
			),
		);

		// -------- update_docs --------
		this.server.tool(
			"update_docs",
			{
				action: z.enum(["create", "update"]).describe("Whether to create a new file or update an existing one"),
				file_path: z.string().min(1).max(200).describe("Path relative to repo root, e.g. 'processes/sales/new-sop.md'"),
				content: z.string().min(1).describe("Full file content (markdown with optional frontmatter)"),
				commit_message: z.string().min(5).max(100).describe("Git commit message"),
				pr_title: z.string().optional().describe("Pull request title (if provided, creates a PR)"),
				pr_description: z.string().optional().describe("Pull request description"),
				branch_name: z.string().optional().describe("Custom branch name (auto-generated if not provided)"),
				base_branch: z.string().optional().default("main").describe("Base branch to create PR against"),
			},
			this.withSentryInstrumentation(
				"update_docs",
				() => undefined, // no single app
				async ({
					action,
					file_path,
					content,
					commit_message,
					pr_title,
					pr_description,
					branch_name,
					base_branch,
				}: {
					action: "create" | "update";
					file_path: string;
					content: string;
					commit_message: string;
					pr_title?: string;
					pr_description?: string;
					branch_name?: string;
					base_branch?: string;
				}) => {
					console.log(`📝 Documentation update called for: ${file_path}`);

					const token = this.env.GITHUB_TOKEN;
					if (!token) {
						console.error("❌ GitHub token missing for documentation update");
						return {
							content: [
								{
									type: "text",
									text: JSON.stringify({
										error: "github_not_configured",
										message: "GitHub token not configured for documentation updates",
									}),
								},
							],
						};
					}

					const sopOwner = this.env.GITHUB_SOP_OWNER || "ASISolutions";
					const sopRepo = this.env.GITHUB_SOP_REPO || "docs";
					const apiBase = this.env.GITHUB_API_BASE || "https://api.github.com";

					console.log(`🔧 Using repository: ${sopOwner}/${sopRepo} (API: ${apiBase})`);

					try {
						const docService = new GitHubDocService(
							token,
							sopOwner,
							sopRepo,
							apiBase,
						);

						const updateParams: UpdateDocParams = {
							action,
							file_path,
							content,
							commit_message,
							pr_title,
							pr_description,
							branch_name,
							base_branch,
						};

						console.log(`🚀 Starting ${action} operation for ${file_path}...`);
						const result = await docService.updateDocument(updateParams);

						if (!result.success) {
							console.error(`❌ Documentation update failed: ${result.error}`);
							return {
								content: [
									{
										type: "text",
										text: JSON.stringify({
											error: "update_failed",
											message: `Failed to ${action} documentation: ${result.error}`,
											file_path,
										}),
									},
								],
							};
						}

						console.log(`✅ Documentation ${action} successful`);
						
						// Format response with all relevant information
						const response: any = {
							success: true,
							action,
							file_path,
							branch: result.branch,
							commit_sha: result.commit_sha,
							repository: `${sopOwner}/${sopRepo}`,
						};

						if (result.pr_url) {
							response.pull_request = {
								url: result.pr_url,
								number: result.pr_number,
								title: pr_title,
							};
							response.message = `Documentation ${action}d and pull request created successfully. Review at: ${result.pr_url}`;
						} else {
							response.message = `Documentation ${action}d successfully on branch: ${result.branch}`;
						}

						return {
							content: [
								{
									type: "text",
									text: JSON.stringify(response),
								},
							],
						};
					} catch (error) {
						console.error(`💥 Documentation update error:`, error);
						return {
							content: [
								{
									type: "text",
									text: JSON.stringify({
										error: "update_failed",
										message: `Documentation update failed: ${error instanceof Error ? error.message : "Unknown error"}`,
										file_path,
										action,
									}),
								},
							],
						};
					}
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
				/(authorization|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|key)/i.test(
					k,
				)
			) {
				obj[k] = "[redacted]";
			} else {
				redact(obj[k]);
			}
		}
	};

	// Redact sensitive data from all parts of the event
	redact((event as any).request);
	redact(event.contexts);
	redact(event.extra);
	redact((event as any).breadcrumbs);

	// Also scrub log messages for sensitive content
	if (event.message) {
		event.message = event.message.replace(
			/(token|password|secret|key)\s*[=:]\s*[^\s]+/gi,
			"$1=[redacted]",
		);
	}

	// Scrub breadcrumb messages
	if (event.breadcrumbs) {
		event.breadcrumbs = event.breadcrumbs.map((breadcrumb) => {
			if (breadcrumb.message) {
				breadcrumb.message = breadcrumb.message.replace(
					/(token|password|secret|key)\s*[=:]\s*[^\s]+/gi,
					"$1=[redacted]",
				);
			}
			redact(breadcrumb.data);
			return breadcrumb;
		});
	}

	return event;
}

// HTML content for auth pages
const authSuccessHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Success</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background-color: #f5f5f5;
        }
        .container {
            text-align: center;
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            max-width: 400px;
        }
        .success-icon {
            color: #22c55e;
            font-size: 3rem;
            margin-bottom: 1rem;
        }
        h1 {
            color: #1f2937;
            margin-bottom: 0.5rem;
        }
        p {
            color: #6b7280;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✓</div>
        <h1>Authentication Successful</h1>
        <p>You have successfully connected your account. You can now close this window and return to your application.</p>
    </div>
</body>
</html>`;

const authFailureHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Failed</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background-color: #f5f5f5;
        }
        .container {
            text-align: center;
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            max-width: 400px;
        }
        .error-icon {
            color: #ef4444;
            font-size: 3rem;
            margin-bottom: 1rem;
        }
        h1 {
            color: #1f2937;
            margin-bottom: 0.5rem;
        }
        p {
            color: #6b7280;
            line-height: 1.5;
        }
        .retry-text {
            margin-top: 1rem;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">✗</div>
        <h1>Authentication Failed</h1>
        <p>There was an error connecting your account. Please try again or contact support if the problem persists.</p>
        <p class="retry-text">You can close this window and retry the authentication process.</p>
    </div>
</body>
</html>`;

// Create the OAuth Provider instance
const provider = new OAuthProvider({
	// Protect both the HTTP and SSE MCP endpoints
	apiHandlers: {
		"/mcp": ASIConnectMCP.serve("/mcp") as any,
		"/sse": ASIConnectMCP.serveSSE("/sse") as any,
		// Add auth page handlers as ExportedHandler objects
		"/auth/success": {
			fetch: async () => {
				return new Response(authSuccessHtml, {
					headers: {
						"Content-Type": "text/html",
						"Cache-Control": "public, max-age=3600",
					},
				});
			},
		},
		"/auth/failure": {
			fetch: async () => {
				return new Response(authFailureHtml, {
					headers: {
						"Content-Type": "text/html",
						"Cache-Control": "public, max-age=3600",
					},
				});
			},
		},
	},
	// The UI / SSO flow is handled by Access in our default handler
	defaultHandler: AccessDefaultHandler,
	// OAuth endpoints surfaced by the provider
	authorizeEndpoint: "/authorize",
	tokenEndpoint: "/token",
	clientRegistrationEndpoint: "/register",
	scopesSupported: ["openid", "email", "profile"],
});

// Custom console wrapper to ensure all logs reach Sentry
function wrapConsoleForSentry() {
	const originalConsole = {
		log: console.log,
		error: console.error,
		warn: console.warn,
		info: console.info,
		debug: console.debug,
	};

	// Wrap console methods to also send to Sentry as messages
	console.log = (...args) => {
		originalConsole.log(...args);
		try {
			if (typeof Sentry !== "undefined") {
				Sentry.addBreadcrumb({
					message: args
						.map((arg) =>
							typeof arg === "object" ? JSON.stringify(arg) : String(arg),
						)
						.join(" "),
					level: "info",
					category: "console",
				});
			}
		} catch (e) {
			// Silent fallback
		}
	};

	console.info = (...args) => {
		originalConsole.info(...args);
		try {
			if (typeof Sentry !== "undefined") {
				Sentry.addBreadcrumb({
					message: args
						.map((arg) =>
							typeof arg === "object" ? JSON.stringify(arg) : String(arg),
						)
						.join(" "),
					level: "info",
					category: "console",
				});
			}
		} catch (e) {
			// Silent fallback
		}
	};

	console.warn = (...args) => {
		originalConsole.warn(...args);
		try {
			if (typeof Sentry !== "undefined") {
				Sentry.addBreadcrumb({
					message: args
						.map((arg) =>
							typeof arg === "object" ? JSON.stringify(arg) : String(arg),
						)
						.join(" "),
					level: "warning",
					category: "console",
				});
			}
		} catch (e) {
			// Silent fallback
		}
	};

	console.error = (...args) => {
		originalConsole.error(...args);
		try {
			if (typeof Sentry !== "undefined") {
				Sentry.addBreadcrumb({
					message: args
						.map((arg) =>
							typeof arg === "object" ? JSON.stringify(arg) : String(arg),
						)
						.join(" "),
					level: "error",
					category: "console",
				});
				// Also capture errors as Sentry events for visibility
				const errorMessage = args
					.map((arg) =>
						typeof arg === "object" ? JSON.stringify(arg) : String(arg),
					)
					.join(" ");
				Sentry.captureMessage(errorMessage, "error");
			}
		} catch (e) {
			// Silent fallback
		}
	};

	console.debug = (...args) => {
		originalConsole.debug(...args);
		try {
			if (typeof Sentry !== "undefined") {
				Sentry.addBreadcrumb({
					message: args
						.map((arg) =>
							typeof arg === "object" ? JSON.stringify(arg) : String(arg),
						)
						.join(" "),
					level: "debug",
					category: "console",
				});
			}
		} catch (e) {
			// Silent fallback
		}
	};

	return originalConsole;
}

// Helper to safely wrap with Sentry or fallback gracefully
function createSentryWrappedHandler(provider: unknown): ExportedHandler<Env> {
	return {
		fetch: async (request, env, ctx) => {
			// Check if Sentry should be enabled
			if (!env.SENTRY_DSN) {
				console.log(
					"Sentry DSN not configured, running without Sentry monitoring",
				);
				return (provider as any).fetch(request, env, ctx);
			}

			// Wrap console methods to ensure all logs reach Sentry
			wrapConsoleForSentry();

			// Log startup with Sentry integration
			console.log(`🚀 ASI MCP Server starting with Sentry integration enabled`);
			console.log(
				`📊 Sentry Environment: ${env.SENTRY_ENV ?? env.PIPEDREAM_ENV}`,
			);
			console.log(`🔢 Release: ${env.CF_VERSION_METADATA?.id || "dev"}`);

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
							// Enhanced logging configuration
							enableLogs: true,
							// Capture all log levels (debug, info, warn, error)
							logLevels: ["debug", "info", "warn", "error"],
							// Send console.* calls immediately without batching delays
							beforeBreadcrumb: (breadcrumb) => {
								// Enhance console breadcrumbs with more context
								if (breadcrumb.category === "console") {
									breadcrumb.level = breadcrumb.level || "info";
									breadcrumb.timestamp = Date.now() / 1000;
								}
								return breadcrumb;
							},
							// Tracing: 100% since volume is low (tune later)
							tracesSampleRate: 1.0,
							// Capture more breadcrumbs to provide better context
							maxBreadcrumbs: 100,
							// Enable debug mode for development
							debug: env.SENTRY_ENV === "development",
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
				console.error(
					"Sentry initialization failed, falling back to direct execution:",
					sentryError,
				);
				// Fallback to direct provider execution
				return (provider as any).fetch(request, env, ctx);
			}
		},
	};
}

// Export the OAuth Provider with resilient Sentry wrapper
export default createSentryWrappedHandler(provider);
