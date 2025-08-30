import type { Env } from "./index";
import {
	parseJWT,
	verifyToken,
	fetchUpstreamAuthToken,
} from "./workers-oauth-utils";

/**
 * Validates and sanitizes tenant ID to prevent collisions and injection
 */
function validateTenantId(tenantId: string): string {
	const cleaned = tenantId.toLowerCase().replace(/[^a-z0-9-]/g, "");
	if (cleaned.length === 0 || cleaned.length > 50) {
		throw new Error("Invalid tenant ID format");
	}
	// Prevent reserved names
	const reserved = ["www", "api", "admin", "default", "system", "internal"];
	if (reserved.includes(cleaned)) {
		return `tenant-${cleaned}`;
	}
	return cleaned;
}

/**
 * Derives tenant ID from URL hostname or Access claims with collision prevention
 */
function deriveTenantId(requestUrl: string, claims: any): string {
	try {
		// Priority 1: Explicit org claims from Access
		if (claims.org_id) {
			return validateTenantId(claims.org_id);
		}
		if (claims.organization) {
			return validateTenantId(claims.organization);
		}

		// Priority 2: Hostname-based with collision prevention
		const hostname = new URL(requestUrl).hostname.toLowerCase();
		const parts = hostname.split(".");

		if (parts.length >= 3) {
			// For multi-subdomain like "acme.mcp.example.com"
			const subdomain = parts[0];
			if (subdomain.length >= 3 && subdomain !== "www") {
				// Include second level for uniqueness: "acme-mcp"
				const secondLevel = parts[1];
				if (secondLevel && secondLevel !== "mcp") {
					return validateTenantId(`${subdomain}-${secondLevel}`);
				}
				return validateTenantId(subdomain);
			}
		}

		// Priority 3: Email domain with TLD for uniqueness
		const email = claims.email || "";
		if (email.includes("@")) {
			const domain = email.split("@")[1];
			if (domain) {
				// Use full domain to prevent collisions: "acme.com" vs "acme.co.uk"
				return validateTenantId(domain.replace(/\./g, "-"));
			}
		}

		// Fallback
		return "default";
	} catch (error) {
		console.warn("Tenant ID derivation failed:", error);
		return "default";
	}
}

/**
 * Default handler used by OAuthProvider. It implements the /authorize UI endpoint
 * and uses Cloudflare Access as the SSO layer. After Access authenticates the user,
 * this handler completes the OAuth flow by calling env.OAUTH_PROVIDER.completeAuthorization().
 */
export default {
	async fetch(request: Request, env: any, ctx: ExecutionContext) {
		const url = new URL(request.url);

		if (url.pathname === "/authorize") {
			// If returning from Access, there will be a `code` and `state` param
			const code = url.searchParams.get("code");
			const state = url.searchParams.get("state");

			if (!code) {
				// Initial request from MCP client
				// Ensure the OAuth client is registered with the requested redirect URI
				const clientId = url.searchParams.get("client_id");
				const reqRedirectUri = url.searchParams.get("redirect_uri");
				if (clientId && reqRedirectUri) {
					try {
						const existing = await env.OAUTH_PROVIDER.lookupClient(clientId);
						if (!existing) {
							await env.OAUTH_PROVIDER.createClient({
								clientId,
								redirectUris: [reqRedirectUri],
								tokenEndpointAuthMethod: "none",
							});
						} else if (!existing.redirectUris?.includes(reqRedirectUri)) {
							const updatedUris = Array.from(
								new Set([...(existing.redirectUris || []), reqRedirectUri]),
							);
							await env.OAUTH_PROVIDER.updateClient(clientId, {
								redirectUris: updatedUris,
							});
						}
					} catch {
						// non-fatal in dev, parseAuthRequest may still succeed if already valid
					}
				}

				// Parse and persist OAuth request by state
				const oauthReq = await env.OAUTH_PROVIDER.parseAuthRequest(request);
				// Persist the parsed request so we can complete after redirect back
				await env.OAUTH_KV.put(
					`oauthreq:${oauthReq.state}`,
					JSON.stringify(oauthReq),
					{ expirationTtl: 600 },
				);

				// Redirect to Cloudflare Access (acts as upstream OAuth provider)
				const redirectUri = `${url.origin}/authorize`;
				const authEndpoint = normalizeEndpoint(
					env.ACCESS_AUTHORIZATION_URL,
					url,
				);
				const login = new URL(authEndpoint);
				login.searchParams.set("client_id", env.ACCESS_CLIENT_ID);
				login.searchParams.set("redirect_uri", redirectUri);
				login.searchParams.set("response_type", "code");
				login.searchParams.set("state", oauthReq.state);
				login.searchParams.set("scope", "openid email profile");
				return Response.redirect(login.toString(), 302);
			}

			// Callback from Access: load saved oauth request
			if (!state) {
				return new Response("Missing state", { status: 400 });
			}
			const saved = await env.OAUTH_KV.get(`oauthreq:${state}`);
			if (!saved) {
				return new Response("Invalid or expired state", { status: 400 });
			}
			const oauthReq = JSON.parse(saved);

			// Exchange code for tokens with Access
			const redirectUri = `${url.origin}/authorize`;
			const tokenEndpoint = normalizeEndpoint(env.ACCESS_TOKEN_URL, url);
			const tokens = await fetchUpstreamAuthToken(
				tokenEndpoint,
				env.ACCESS_CLIENT_ID,
				env.ACCESS_CLIENT_SECRET,
				code,
				redirectUri,
			);

			// Derive identity from ID token if present
			let claims: any = {};
			try {
				const idToken = tokens.id_token as string | undefined;
				if (idToken) {
					claims = parseJWT(idToken).payload;
				}
			} catch (err) {
				// ignore, fall back to minimal claims
			}

			const userId = String(
				claims.sub || claims.email || claims.user_id || "unknown",
			);

			// Derive tenant_id from hostname or Access claims with collision prevention
			const tenant_id = deriveTenantId(request.url, claims);

			const props = {
				sub: userId,
				email: claims.email || "",
				name: claims.name || claims.common_name || "",
				tenant_id,
				access: {
					id_token: tokens.id_token,
					expires_in: tokens.expires_in,
				},
			};

			const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
				request: oauthReq,
				userId,
				metadata: { provider: "cloudflare-access" },
				scope: oauthReq.scope,
				props,
			});

			// Cleanup
			await env.OAUTH_KV.delete(`oauthreq:${state}`);

			return Response.redirect(redirectTo, 302);
		}

		return new Response("Not found", { status: 404 });
	},
};

function normalizeEndpoint(endpoint: string | undefined, reqUrl: URL): string {
	if (!endpoint || typeof endpoint !== "string") {
		throw new Error("Missing Access endpoint configuration");
	}
	if (/^https?:\/\//i.test(endpoint)) return endpoint;
	const path = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
	return new URL(path, reqUrl.origin).toString();
}
