// src/dicker-data-auth.ts
import type { Env } from "./index";

export interface DickerDataCredentials {
	account: string;
	username: string;
	password: string;
}

export interface DickerDataSession {
	cookieString: string;
	expiresAt: number;
	lastRefresh: number;
}

export class DickerDataAuth {
	private env: Env;
	private sessionKey: string;

	constructor(env: Env, tenant?: string, user?: string) {
		this.env = env;
		const tenantId = tenant || "default";
		const userId = user || "unknown";
		this.sessionKey = `tenant:${tenantId}:user:${userId}:dicker-data:session`;
	}

	private getCredentials(): DickerDataCredentials {
		const account = this.env.DICKER_DATA_ACCOUNT;
		const username = this.env.DICKER_DATA_USERNAME;
		const password = this.env.DICKER_DATA_PASSWORD;

		if (!account || !username || !password) {
			throw new Error("Dicker Data credentials not configured");
		}

		return { account, username, password };
	}

	private async getStoredSession(): Promise<DickerDataSession | null> {
		try {
			const stored = await this.env.USER_LINKS.get(this.sessionKey);
			if (!stored) return null;

			const session = JSON.parse(stored) as DickerDataSession;

			// Check if session is expired (sessions typically last 24 hours, we refresh after 12)
			const now = Date.now();
			if (now > session.expiresAt) {
				await this.env.USER_LINKS.delete(this.sessionKey);
				return null;
			}

			return session;
		} catch (error) {
			console.error("Failed to get stored Dicker Data session:", error);
			return null;
		}
	}

	private async storeSession(cookieString: string): Promise<void> {
		const now = Date.now();
		const session: DickerDataSession = {
			cookieString,
			expiresAt: now + 12 * 60 * 60 * 1000, // 12 hours
			lastRefresh: now,
		};

		try {
			await this.env.USER_LINKS.put(
				this.sessionKey,
				JSON.stringify(session),
				{ expirationTtl: 24 * 60 * 60 }, // 24 hours TTL
			);
		} catch (error) {
			console.error("Failed to store Dicker Data session:", error);
			throw error;
		}
	}

	private async performLogin(): Promise<string> {
		const { account, username, password } = this.getCredentials();

		console.log("🔐 Starting Dicker Data authentication...");

		// Step 1: Get login page and CSRF token
		const loginPageResponse = await fetch(
			"https://portal.dickerdata.co.nz/Account/Login?ReturnUrl=%2Fhome",
			{
				method: "GET",
				headers: {
					"User-Agent":
						"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
					Accept:
						"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
				},
			},
		);

		if (!loginPageResponse.ok) {
			throw new Error(`Failed to get login page: ${loginPageResponse.status}`);
		}

		const loginPageHtml = await loginPageResponse.text();
		const setCookieHeaders = loginPageResponse.headers.get("set-cookie");

		// Extract CSRF token
		const tokenMatch = loginPageHtml.match(
			/name="__RequestVerificationToken"[^>]*value="([^"]+)"/,
		);
		if (!tokenMatch) {
			throw new Error("Could not extract CSRF token from login page");
		}
		const csrfToken = tokenMatch[1];
		console.log("🔑 CSRF token extracted successfully");

		// Extract initial cookies
		const initialCookies = this.parseCookies(setCookieHeaders || "");

		// Step 2: Perform login
		const formData = new URLSearchParams({
			ReturnUrl: "/home",
			Username: username,
			AccountId: account,
			Password: password,
			__RequestVerificationToken: csrfToken,
			RememberLogin: "false",
		});

		const loginResponse = await fetch(
			"https://portal.dickerdata.co.nz/Account/Login?ReturnUrl=%2Fhome",
			{
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					"User-Agent":
						"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
					Accept:
						"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
					"Accept-Language": "en-US,en;q=0.9",
					"Cache-Control": "max-age=0",
					Origin: "https://portal.dickerdata.co.nz",
					Referer:
						"https://portal.dickerdata.co.nz/Account/Login?ReturnUrl=%2Fhome",
					"Sec-Ch-Ua":
						'"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
					"Sec-Ch-Ua-Mobile": "?0",
					"Sec-Ch-Ua-Platform": '"macOS"',
					"Sec-Fetch-Dest": "document",
					"Sec-Fetch-Mode": "navigate",
					"Sec-Fetch-Site": "same-origin",
					"Sec-Fetch-User": "?1",
					"Upgrade-Insecure-Requests": "1",
					Cookie: initialCookies,
				},
				body: formData,
				redirect: "manual", // Handle redirects manually to capture cookies
			},
		);

		const loginSetCookies = loginResponse.headers.get("set-cookie");
		const allCookies = this.mergeCookies(initialCookies, loginSetCookies || "");

		// Check if login was successful by looking at status code and cookies
		if (loginResponse.status === 302 || loginResponse.status === 200) {
			// Look for session cookies that indicate successful login
			if (
				allCookies.includes("DickerDataCookie") ||
				allCookies.includes("AccountId")
			) {
				console.log("✅ Dicker Data login successful!");
				return allCookies;
			}
		}

		console.error("❌ Dicker Data login failed");
		console.error("Response status:", loginResponse.status);
		console.error(
			"Response headers:",
			Object.fromEntries(loginResponse.headers.entries()),
		);

		throw new Error(`Login failed with status ${loginResponse.status}`);
	}

	private parseCookies(setCookieHeader: string): string {
		if (!setCookieHeader) return "";

		// More robust cookie parsing that handles various Set-Cookie formats
		const cookies: string[] = [];

		// Split by comma, but be careful of dates and other comma-containing values
		const cookieParts = setCookieHeader.split(/,\s*(?=[\w]+=)/);

		for (const part of cookieParts) {
			const trimmed = part.trim();
			if (!trimmed) continue;

			// Extract just the name=value portion (before first semicolon)
			const nameValueMatch = trimmed.match(/^([^=]+=[^;]*)/);
			if (nameValueMatch) {
				const nameValue = nameValueMatch[1].trim();
				// Validate it's a proper cookie format
				if (nameValue.includes("=") && !nameValue.startsWith("=")) {
					cookies.push(nameValue);
				}
			}
		}

		return cookies.join("; ");
	}

	private mergeCookies(existing: string, newSetCookie: string): string {
		const existingCookies = existing ? existing.split("; ") : [];
		const newCookies = this.parseCookies(newSetCookie)
			.split("; ")
			.filter((c) => c);

		// Create a map to handle cookie updates
		const cookieMap = new Map<string, string>();

		// Add existing cookies
		existingCookies.forEach((cookie) => {
			const [name, value] = cookie.split("=", 2);
			if (name && value) {
				cookieMap.set(name, value);
			}
		});

		// Update with new cookies
		newCookies.forEach((cookie) => {
			const [name, value] = cookie.split("=", 2);
			if (name && value) {
				cookieMap.set(name, value);
			}
		});

		// Convert back to cookie string
		return Array.from(cookieMap.entries())
			.map(([name, value]) => `${name}=${value}`)
			.join("; ");
	}

	async getValidSession(): Promise<string> {
		// Try to get existing session
		const stored = await this.getStoredSession();
		if (stored) {
			console.log("🍪 Using cached Dicker Data session");
			return stored.cookieString;
		}

		// No valid session, perform login
		console.log("🔄 No valid session found, performing fresh login");
		const cookieString = await this.performLogin();
		await this.storeSession(cookieString);

		return cookieString;
	}

	async testSession(cookieString: string): Promise<boolean> {
		try {
			// Test the session by making a simple request to a protected page
			const response = await fetch("https://portal.dickerdata.co.nz/home", {
				headers: {
					Cookie: cookieString,
					"User-Agent":
						"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
				},
				redirect: "manual", // Handle redirects manually to detect login redirects
			});

			// Check for various invalid session indicators
			if (response.status === 401 || response.status === 403) {
				console.log("Session validation failed: Unauthorized response");
				return false;
			}

			// Handle redirect responses
			if (response.status >= 300 && response.status < 400) {
				const location = response.headers.get("location");
				if (location) {
					const locationLower = location.toLowerCase();
					// Check for various login/auth redirect patterns
					if (
						locationLower.includes("login") ||
						locationLower.includes("signin") ||
						locationLower.includes("auth") ||
						locationLower.includes("account/login")
					) {
						console.log(
							"Session validation failed: Redirected to authentication page",
						);
						return false;
					}
				}
			}

			// Check response content for login indicators (as fallback)
			if (response.ok) {
				const contentType = response.headers.get("content-type") || "";
				if (contentType.includes("text/html")) {
					const text = await response.text();
					const textLower = text.toLowerCase();
					// Look for login form indicators in the HTML content
					if (
						textLower.includes("<form") &&
						(textLower.includes('action="login') ||
							textLower.includes('action="/account/login') ||
							(textLower.includes('name="password"') &&
								textLower.includes('name="username"')))
					) {
						console.log(
							"Session validation failed: Login form detected in response",
						);
						return false;
					}
				}
			}

			return response.ok;
		} catch (error) {
			console.error("Session test failed:", error);
			return false;
		}
	}

	async refreshSessionIfNeeded(): Promise<string> {
		const session = await this.getStoredSession();

		// If no session or expired, get a fresh one
		if (!session) {
			return this.getValidSession();
		}

		// Test if current session is still valid
		const isValid = await this.testSession(session.cookieString);
		if (isValid) {
			return session.cookieString;
		}

		// Session invalid, clear it and get a fresh one
		console.log("🔄 Session invalid, refreshing Dicker Data authentication");
		await this.env.USER_LINKS.delete(this.sessionKey);
		return this.getValidSession();
	}
}
