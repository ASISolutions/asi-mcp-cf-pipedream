import {
	parseJWT,
	fetchUpstreamAuthToken,
} from "./workers-oauth-utils";
import { UserProvisioningService } from "./user-provisioning";

// HTML content getter functions (to avoid circular imports)
function getAuthSuccessHtml(): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Successful</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 0;
            min-height: 100vh;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 12px;
            padding: 48px 32px;
            text-align: center;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            max-width: 400px;
            width: 90%;
        }
        .checkmark {
            width: 64px;
            height: 64px;
            margin: 0 auto 24px;
            background: #10b981;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .checkmark svg {
            width: 32px;
            height: 32px;
            color: white;
        }
        h1 {
            color: #1f2937;
            margin-bottom: 16px;
            font-size: 24px;
        }
        p {
            color: #6b7280;
            line-height: 1.6;
            margin-bottom: 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="checkmark">
            <svg fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
            </svg>
        </div>
        <h1>Authentication Successful!</h1>
        <p>You have been successfully authenticated. You can now close this window and return to your application.</p>
    </div>
</body>
</html>`;
}

function getAuthFailureHtml(): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Failed</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 0;
            min-height: 100vh;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 12px;
            padding: 48px 32px;
            text-align: center;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            max-width: 400px;
            width: 90%;
        }
        .error-icon {
            width: 64px;
            height: 64px;
            margin: 0 auto 24px;
            background: #ef4444;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .error-icon svg {
            width: 32px;
            height: 32px;
            color: white;
        }
        h1 {
            color: #1f2937;
            margin-bottom: 16px;
            font-size: 24px;
        }
        p {
            color: #6b7280;
            line-height: 1.6;
            margin-bottom: 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">
            <svg fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
            </svg>
        </div>
        <h1>Authentication Failed</h1>
        <p>Sorry, we couldn't authenticate you. Please try again or contact support if the problem persists.</p>
    </div>
</body>
</html>`;
}

function getSignupHtml(): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Join ASI Connect MCP</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #2d3748;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .signup-container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.15);
            max-width: 480px;
            width: 100%;
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
            padding: 40px 32px;
            text-align: center;
            color: white;
        }

        .logo {
            width: 48px;
            height: 48px;
            margin: 0 auto 16px;
            background: rgba(255, 255, 255, 0.2);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .header h1 {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 8px;
        }

        .header p {
            font-size: 16px;
            opacity: 0.9;
        }

        .content {
            padding: 40px 32px;
        }

        .microsoft-btn {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            padding: 16px 24px;
            background: #0078d4;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 16px;
            transition: all 0.2s ease;
            margin-bottom: 32px;
            border: none;
        }

        .microsoft-btn:hover {
            background: #106ebe;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 120, 212, 0.3);
        }

        .microsoft-icon {
            width: 20px;
            height: 20px;
            margin-right: 12px;
        }

        .features {
            margin-bottom: 32px;
        }

        .feature-item {
            display: flex;
            align-items: center;
            margin-bottom: 16px;
        }

        .feature-item:last-child {
            margin-bottom: 0;
        }

        .checkmark {
            width: 20px;
            height: 20px;
            color: #10b981;
            margin-right: 12px;
            flex-shrink: 0;
        }

        .feature-item span {
            color: #4b5563;
        }

        .divider {
            height: 1px;
            background: #e5e7eb;
            margin: 32px 0;
        }

        .footer-text {
            text-align: center;
            font-size: 14px;
            color: #6b7280;
        }

        .footer-text a {
            color: #4f46e5;
            text-decoration: none;
        }

        .footer-text a:hover {
            text-decoration: underline;
        }

        @media (max-width: 480px) {
            .signup-container {
                margin: 10px;
            }
            
            .header {
                padding: 32px 24px;
            }
            
            .content {
                padding: 32px 24px;
            }
        }
    </style>
</head>
<body>
    <div class="signup-container">
        <div class="header">
            <div class="logo">
                <svg width="24" height="24" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/>
                </svg>
            </div>
            <h1>Join ASI Connect MCP</h1>
            <p>Your secure bridge to business applications</p>
        </div>

        <div class="content">
            <a href="/authorize?signup=true" class="microsoft-btn">
                <svg class="microsoft-icon" viewBox="0 0 23 23" fill="currentColor">
                    <path d="M11 11h11v11H11z"/>
                    <path d="M0 11h11v11H0z"/>
                    <path d="M11 0h11v11H11z"/>
                    <path d="M0 0h11v11H0z"/>
                </svg>
                Sign up with Microsoft
            </a>

            <div class="features">
                <div class="feature-item">
                    <svg class="checkmark" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                    </svg>
                    <span>30-day free trial with full access</span>
                </div>
                <div class="feature-item">
                    <svg class="checkmark" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                    </svg>
                    <span>Enterprise-grade security and compliance</span>
                </div>
                <div class="feature-item">
                    <svg class="checkmark" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                    </svg>
                    <span>Connect to 100+ business applications</span>
                </div>
                <div class="feature-item">
                    <svg class="checkmark" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                    </svg>
                    <span>Dedicated GitBook documentation space</span>
                </div>
            </div>

            <div class="divider"></div>

            <div class="footer-text">
                By signing up, you agree to our <a href="#">Terms of Service</a> and <a href="#">Privacy Policy</a>
            </div>
        </div>
    </div>
</body>
</html>`;
}

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
function deriveTenantId(requestUrl: string, claims: Record<string, unknown>): string {
	try {
		// Priority 1: Explicit org claims from Access
		if (claims.org_id && typeof claims.org_id === 'string') {
			return validateTenantId(claims.org_id);
		}
		if (claims.organization && typeof claims.organization === 'string') {
			return validateTenantId(claims.organization);
		}

		// Priority 2: Hostname-based with collision prevention
		const hostname = new URL(requestUrl).hostname.toLowerCase();
		const parts = hostname.split(".");

		if (parts.length >= 3) {
			const subdomain = parts[0];
			if (subdomain.length >= 3 && subdomain !== "www") {
				// Handle ASI MCP production domains: [tenant].mcp.asi.nz
				if (hostname.endsWith('.mcp.asi.nz')) {
					return validateTenantId(subdomain);
				}

				// Handle Cloudflare Workers URLs (*.*.workers.dev)
				if (
					parts[parts.length - 2] === "workers" &&
					parts[parts.length - 1] === "dev"
				) {
					// For "asi-mcp.asi-cloud.workers.dev" → just use "asi-mcp"
					return validateTenantId(subdomain);
				}

				// For other custom domains, include second level for uniqueness
				// Example: "acme.api.example.com" → "acme-api"
				const secondLevel = parts[1];
				if (secondLevel) {
					return validateTenantId(`${subdomain}-${secondLevel}`);
				}
				return validateTenantId(subdomain);
			}
		}

		// Priority 3: Email domain with TLD for uniqueness
		const email = (claims.email as string) || "";
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
	async fetch(request: Request, env: unknown, ctx: ExecutionContext) {
		const url = new URL(request.url);

		// Handle public routes that don't require authentication
		if (url.pathname === "/auth/success") {
			return new Response(getAuthSuccessHtml(), {
				headers: {
					"Content-Type": "text/html",
					"Cache-Control": "public, max-age=3600",
				},
			});
		}

		if (url.pathname === "/auth/failure") {
			return new Response(getAuthFailureHtml(), {
				headers: {
					"Content-Type": "text/html",
					"Cache-Control": "public, max-age=3600",
				},
			});
		}

		if (url.pathname === "/signup") {
			return new Response(getSignupHtml(), {
				headers: {
					"Content-Type": "text/html",
					"Cache-Control": "public, max-age=3600",
				},
			});
		}

		if (url.pathname === "/welcome") {
			// Redirect /welcome to /signup
			return Response.redirect(new URL("/signup", url.origin).toString(), 302);
		}

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
						const existing = await (env as any).OAUTH_PROVIDER.lookupClient(clientId);
						if (!existing) {
							await (env as any).OAUTH_PROVIDER.createClient({
								clientId,
								redirectUris: [reqRedirectUri],
								tokenEndpointAuthMethod: "none",
							});
						} else if (!existing.redirectUris?.includes(reqRedirectUri)) {
							const updatedUris = Array.from(
								new Set([...(existing.redirectUris || []), reqRedirectUri]),
							);
							await (env as any).OAUTH_PROVIDER.updateClient(clientId, {
								redirectUris: updatedUris,
							});
						}
					} catch {
						// non-fatal in dev, parseAuthRequest may still succeed if already valid
					}
				}

				// Parse and persist OAuth request by state
				const oauthReq = await (env as any).OAUTH_PROVIDER.parseAuthRequest(request);
				// Persist the parsed request so we can complete after redirect back
				await (env as any).OAUTH_KV.put(
					`oauthreq:${oauthReq.state}`,
					JSON.stringify(oauthReq),
					{ expirationTtl: 600 },
				);

				// Redirect to Cloudflare Access (acts as upstream OAuth provider)
				const redirectUri = `${url.origin}/authorize`;
				const authEndpoint = normalizeEndpoint(
					(env as any).ACCESS_AUTHORIZATION_URL,
					url,
				);
				const login = new URL(authEndpoint);
				login.searchParams.set("client_id", (env as any).ACCESS_CLIENT_ID);
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
			const saved = await (env as any).OAUTH_KV.get(`oauthreq:${state}`);
			if (!saved) {
				return new Response("Invalid or expired state", { status: 400 });
			}
			const oauthReq = JSON.parse(saved);

			// Exchange code for tokens with Access
			const redirectUri = `${url.origin}/authorize`;
			const tokenEndpoint = normalizeEndpoint((env as any).ACCESS_TOKEN_URL, url);
			const tokens = await fetchUpstreamAuthToken(
				tokenEndpoint,
				(env as any).ACCESS_CLIENT_ID,
				(env as any).ACCESS_CLIENT_SECRET,
				code,
				redirectUri,
			);

			// Derive identity from ID token if present
			let claims: Record<string, unknown> = {};
			try {
				const idToken = tokens.id_token as string | undefined;
				if (idToken) {
					claims = parseJWT(idToken).payload;
				}
			} catch (_err) {
				// ignore, fall back to minimal claims
			}

			const userId = String(
				claims.sub || claims.email || claims.user_id || "unknown",
			);

			// Derive tenant_id from hostname or Access claims with collision prevention
			const tenant_id = deriveTenantId(request.url, claims);
			
			// Check if this is a signup flow
			const isSignup = url.searchParams.get("signup") === "true" || oauthReq.client_id?.includes("signup");
			
			const userEmail = (claims.email as string) || "";
			const userDomain = userEmail.includes("@") ? userEmail.split("@")[1] : "";
			
			// Initialize provisioning service
			const provisioning = new UserProvisioningService(env as any);
			
			// Check if user already exists
			const userExists = await provisioning.userExists(tenant_id, userId);
			
			if (!userExists) {
				// New user signup flow
				if (!isSignup) {
					// User doesn't exist but this isn't a signup request - redirect to signup
					const signupUrl = new URL("/signup", url.origin);
					return Response.redirect(signupUrl.toString(), 302);
				}
				
				// Check domain blocking
				if (userDomain) {
					const domainCheck = await provisioning.isDomainBlocked(userDomain);
					if (domainCheck.blocked) {
						// Return error page for blocked domain
						return new Response(`
							<!DOCTYPE html>
							<html><head><title>Domain Already Registered</title></head>
							<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;">
								<h1 style="color: #e53e3e;">Domain Already Registered</h1>
								<p>${domainCheck.reason}</p>
								<p>If you believe this is an error, please contact support.</p>
								<a href="/signup" style="color: #3182ce;">← Back to Sign Up</a>
							</body></html>
						`, {
							status: 403,
							headers: { "Content-Type": "text/html" }
						});
					}
				}
				
				// Create new user and start provisioning
				await provisioning.createUser({
					tenant: tenant_id,
					sub: userId,
					email: userEmail,
					name: (claims.name as string) || (claims.common_name as string) || "",
					domain: userDomain
				});
				
				// Start async provisioning (don't await - let it run in background)
				ctx.waitUntil(provisioning.completeProvisioning(tenant_id, userId));
			}

			const props = {
				sub: userId,
				email: (claims.email as string) || "",
				name: (claims.name as string) || (claims.common_name as string) || "",
				tenant_id,
				access: {
					id_token: tokens.id_token,
					expires_in: tokens.expires_in,
				},
			};

			const { redirectTo } = await (env as any).OAUTH_PROVIDER.completeAuthorization({
				request: oauthReq,
				userId,
				metadata: { provider: "cloudflare-access" },
				scope: oauthReq.scope,
				props,
			});

			// Cleanup
			await (env as any).OAUTH_KV.delete(`oauthreq:${state}`);

			// If this was a new user signup, redirect to dashboard instead of original redirect
			if (!userExists && isSignup) {
				const dashboardUrl = new URL("/dashboard", url.origin);
				return Response.redirect(dashboardUrl.toString(), 302);
			}

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
