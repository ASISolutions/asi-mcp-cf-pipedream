# ASI Connect MCP Server

A production-ready remote MCP (Model Context Protocol) server that runs on Cloudflare Workers, integrates with Cloudflare Zero Trust for authentication, and uses Pipedream Connect to manage OAuth connections for HubSpot, Xero, and PandaDoc.

## Features

- **Remote MCP Server**: Runs on Cloudflare Workers with SSE transport
- **Zero Trust Authentication**: Protected with Cloudflare Access for SaaS OAuth
- **Multi-App OAuth**: Uses Pipedream Connect to manage HubSpot, Xero, and PandaDoc connections
- **Intelligent Routing**: Auto-detects destination app from URLs and injects correct tokens
- **Xero Tenant Handling**: Automatically manages Xero tenant IDs with caching

## MCP Tools

### 1. `auth.status`
Check authentication status for connected apps.

**Parameters:**
- `apps` (optional): Array of apps to filter [`"hubspot"`, `"xero"`, `"pandadoc"`]

**Example:**
```json
{ "tool": "auth.status", "args": {} }
```

### 2. `auth.connect`  
Get a Pipedream Connect Link to authenticate with an app.

**Parameters:**
- `app` (required): App to connect [`"hubspot"`, `"xero"`, `"pandadoc"`]

**Example:**
```json
{ "tool": "auth.connect", "args": { "app": "hubspot" } }
```

### 3. `auth.disconnect`
Disconnect from an app and remove stored credentials.

**Parameters:**
- `app` (required): App to disconnect [`"hubspot"`, `"xero"`, `"pandadoc"`]
- `account_id` (optional): Specific account ID to disconnect

**Example:**
```json
{ "tool": "auth.disconnect", "args": { "app": "xero" } }
```

### 4. `http.request`
Make authenticated HTTP requests to supported APIs.

**Parameters:**
- `method` (required): HTTP method [`"GET"`, `"POST"`, `"PUT"`, `"PATCH"`, `"DELETE"`]
- `url` (required): Full API URL
- `headers` (optional): Additional headers
- `body` (optional): Request body (string or object)

**Example:**
```json
{
  "tool": "http.request",
  "args": {
    "method": "GET",
    "url": "https://api.hubapi.com/crm/v3/objects/contacts?limit=5"
  }
}
```

## Setup

### 1. Prerequisites

- Cloudflare account with Workers and Zero Trust
- Pipedream account with Connect project
- OAuth apps configured in HubSpot, Xero, and PandaDoc

### 2. Clone and Install

```bash
cd my-mcp
npm install
```

### 3. Configure Cloudflare Zero Trust (Access for SaaS)

1. **Create Access for SaaS Application**:
   - Go to **Zero Trust** > **Applications** > **SaaS**
   - Click **Add an Application** > **SaaS**
   - Choose **Custom** application type
   - Set Application name: `ASI Connect MCP`
   - Add redirect URIs:
     - Production: `https://<worker-name>.<account>.workers.dev/callback`
     - Local: `http://localhost:8788/callback`

2. **Configure OIDC Settings**:
   - Note the **Client ID** and **Client Secret**
   - Record the OIDC endpoints:
     - Authorization: `https://<team>.cloudflareaccess.com/oauth2/v2/auth`
     - Token: `https://<team>.cloudflareaccess.com/oauth2/v2/token`
     - JWKS: `https://<team>.cloudflareaccess.com/oauth2/v2/keys`

3. **Create Access Policies**:
   - Define who can access the MCP server
   - Configure MFA, device posture, etc. as needed

### 4. Configure Pipedream Connect

1. Create a Pipedream OAuth client for the Connect API
2. Set up your Connect project with HubSpot, Xero, and PandaDoc apps
3. Ensure you're using your own OAuth clients (not Pipedream's)

### 5. Create KV Namespaces

```bash
# Create KV namespaces
wrangler kv:namespace create "OAUTH_KV"
wrangler kv:namespace create "USER_LINKS"

# For preview
wrangler kv:namespace create "OAUTH_KV" --preview
wrangler kv:namespace create "USER_LINKS" --preview
```

Update `wrangler.jsonc` with the returned KV namespace IDs.

### 6. Configure Secrets

Copy `.env.example` to `.env` and fill in your values, then run:

```bash
./setup-secrets.sh
```

Or set secrets manually:

```bash
# Cloudflare Access OAuth
wrangler secret put ACCESS_CLIENT_ID
wrangler secret put ACCESS_CLIENT_SECRET
wrangler secret put ACCESS_AUTHORIZATION_URL
wrangler secret put ACCESS_TOKEN_URL
wrangler secret put ACCESS_JWKS_URL

# Generate cookie encryption key: openssl rand -hex 32
wrangler secret put COOKIE_ENCRYPTION_KEY

# Pipedream Connect
wrangler secret put PIPEDREAM_CLIENT_ID
wrangler secret put PIPEDREAM_CLIENT_SECRET
wrangler secret put PIPEDREAM_PROJECT_ID
wrangler secret put PIPEDREAM_ENV

# Optional redirects
wrangler secret put CONNECT_SUCCESS_REDIRECT
wrangler secret put CONNECT_ERROR_REDIRECT
```

### 7. Local Development

```bash
npx wrangler dev
```

Connect MCP Inspector to `http://localhost:8788/sse`

### 8. Deploy

```bash
npx wrangler deploy
```

Connect from AI Playground or MCP Inspector to `https://<worker>.<account>.workers.dev/sse`

## Usage Examples

### Check Authentication Status
```json
{ "tool": "auth.status", "args": {} }
```

### Connect HubSpot
```json
{ "tool": "auth.connect", "args": { "app": "hubspot" } }
```
→ Returns Connect Link URL to complete OAuth

### Get HubSpot Contacts
```json
{
  "tool": "http.request", 
  "args": {
    "method": "GET",
    "url": "https://api.hubapi.com/crm/v3/objects/contacts?limit=5"
  }
}
```

### Get Xero Invoices  
```json
{
  "tool": "http.request",
  "args": {
    "method": "GET", 
    "url": "https://api.xero.com/api.xro/2.0/Invoices"
  }
}
```
→ Automatically adds `xero-tenant-id` header

### List PandaDoc Documents
```json
{
  "tool": "http.request",
  "args": {
    "method": "GET",
    "url": "https://api.pandadoc.com/public/v1/documents?count=10"
  }
}
```

## Architecture

```
[MCP Client] 
    ↓ Remote MCP over HTTP/SSE
[Cloudflare Worker: MCP Server]
    ↓ OIDC (Access for SaaS)  
[Cloudflare Zero Trust Access]
    ↓ OIDC claims
[MCP Tools] ←→ [Pipedream Connect API] ←→ [HubSpot/Xero/PandaDoc]
```

## Adding More Apps

1. Extend `HOST_TO_APP` mapping in `src/index.ts`
2. Add app to the enum types for tools
3. Configure the app in your Pipedream Connect project
4. The `http.request` tool will automatically handle token injection

## Security

- Keeps Workers OAuth Provider library updated
- Uses Access policies for MFA and device posture
- Never returns raw credentials to clients
- Caches Xero tenant IDs securely in KV

## References

- [Cloudflare MCP Docs](https://developers.cloudflare.com/agents/guides/remote-mcp-server/)
- [Access for SaaS MCP](https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/mcp-servers/saas-mcp/)
- [Pipedream Connect](https://pipedream.com/docs/connect/api-reference/)
- [HubSpot API](https://developers.hubspot.com/docs/guides/apps/authentication/intro-to-auth)
- [Xero API](https://developer.xero.com/documentation/guides/oauth2/auth-flow/)
- [PandaDoc API](https://developers.pandadoc.com/reference/authentication-process)