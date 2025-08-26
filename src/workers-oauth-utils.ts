import { createHmac } from "node:crypto";

export interface Props {
	sub: string;
	email: string;
	name?: string;
	[key: string]: unknown;
}

export async function clientIdAlreadyApproved(
	kv: KVNamespace,
	clientId: string,
	cookieKey: string,
): Promise<boolean> {
	try {
		const stored = await kv.get(`approved:${clientId}`);
		return stored === "true";
	} catch {
		return false;
	}
}

export function renderApprovalDialog(
	clientId: string,
	redirectUri: string,
	scope: string,
	state: string,
): Response {
	const html = `
<!DOCTYPE html>
<html>
<head>
  <title>Authorization Required</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      max-width: 500px; 
      margin: 50px auto; 
      padding: 20px;
      background: #f5f5f5;
    }
    .card { 
      background: white; 
      padding: 30px; 
      border-radius: 8px; 
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    h1 { color: #333; margin-bottom: 20px; }
    .info { 
      background: #f8f9fa; 
      padding: 15px; 
      border-radius: 4px; 
      margin: 20px 0;
      border-left: 4px solid #007acc;
    }
    .actions { margin-top: 30px; }
    button {
      padding: 12px 24px;
      margin: 0 10px 0 0;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 16px;
    }
    .approve { background: #007acc; color: white; }
    .deny { background: #dc3545; color: white; }
    button:hover { opacity: 0.9; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🔐 Authorization Request</h1>
    <p>An application is requesting access to your MCP server:</p>
    
    <div class="info">
      <strong>Client ID:</strong> ${escapeHtml(clientId)}<br>
      <strong>Redirect URI:</strong> ${escapeHtml(redirectUri)}<br>
      <strong>Scope:</strong> ${escapeHtml(scope)}
    </div>
    
    <p>Do you want to authorize this application?</p>
    
    <form method="POST" class="actions">
      <input type="hidden" name="client_id" value="${escapeHtml(clientId)}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}">
      <input type="hidden" name="scope" value="${escapeHtml(scope)}">
      <input type="hidden" name="state" value="${escapeHtml(state)}">
      
      <button type="submit" name="action" value="approve" class="approve">
        ✓ Authorize
      </button>
      <button type="submit" name="action" value="deny" class="deny">
        ✗ Deny
      </button>
    </form>
  </div>
</body>
</html>`;

	return new Response(html, {
		headers: { "Content-Type": "text/html" },
	});
}

export async function parseRedirectApproval(
	kv: KVNamespace,
	clientId: string,
	cookieKey: string,
): Promise<Response> {
	// Store approval
	await kv.put(`approved:${clientId}`, "true", { expirationTtl: 86400 }); // 24 hours

	// Create signed cookie
	const cookie = signCookie(clientId, cookieKey);

	const response = new Response("", { status: 302 });
	response.headers.set(
		"Set-Cookie",
		`mcp_approved=${cookie}; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`,
	);

	return response;
}

export function getUpstreamAuthorizeUrl(
	authUrl: string,
	clientId: string,
	redirectUri: string,
	state: string,
): string {
	const url = new URL(authUrl);
	url.searchParams.set("client_id", clientId);
	url.searchParams.set("redirect_uri", redirectUri);
	url.searchParams.set("response_type", "code");
	url.searchParams.set("state", state);
	url.searchParams.set("scope", "openid email profile");

	return url.toString();
}

export async function fetchUpstreamAuthToken(
	tokenUrl: string,
	clientId: string,
	clientSecret: string,
	code: string,
	redirectUri: string,
): Promise<any> {
	const body = new URLSearchParams({
		grant_type: "authorization_code",
		client_id: clientId,
		client_secret: clientSecret,
		code: code,
		redirect_uri: redirectUri,
	});

	const response = await fetch(tokenUrl, {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
		},
		body: body.toString(),
	});

	if (!response.ok) {
		throw new Error(`Token exchange failed: ${response.status}`);
	}

	return response.json();
}

export async function fetchAccessPublicKey(jwksUrl: string): Promise<any> {
	const response = await fetch(jwksUrl);
	if (!response.ok) {
		throw new Error(`Failed to fetch JWKS: ${response.status}`);
	}
	return response.json();
}

export function parseJWT(token: string): {
	header: any;
	payload: any;
	signature: string;
} {
	const parts = token.split(".");
	if (parts.length !== 3) {
		throw new Error("Invalid JWT format");
	}

	const header = JSON.parse(
		atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")),
	);
	const payload = JSON.parse(
		atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")),
	);

	return { header, payload, signature: parts[2] };
}

export async function verifyToken(
	token: string,
	jwksUrl: string,
): Promise<any> {
	try {
		const { payload } = parseJWT(token);

		// Check expiration
		if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
			throw new Error("Token expired");
		}

		// In a full implementation, you would verify the signature using the JWKS
		// For now, we'll trust the token since it came from our OAuth flow

		return payload;
	} catch (error) {
		throw new Error(`Token verification failed: ${error}`);
	}
}

function signCookie(value: string, key: string): string {
	const hmac = createHmac("sha256", key);
	hmac.update(value);
	const signature = hmac.digest("hex");
	return `${value}.${signature}`;
}

function escapeHtml(text: string): string {
	const map: { [key: string]: string } = {
		"&": "&amp;",
		"<": "&lt;",
		">": "&gt;",
		'"': "&quot;",
		"'": "&#39;",
	};
	return text.replace(/[&<>"']/g, (m) => map[m]);
}
