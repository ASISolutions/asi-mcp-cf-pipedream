# ASI Connect MCP - Complete Setup Guide

This guide walks you through setting up the complete ASI Connect MCP server with Cloudflare Access OAuth and Pipedream Connect integration.

## Architecture Overview

```
[MCP Client (Claude/Inspector)] 
    ↓ (OAuth-protected)
[Cloudflare Worker: ASI Connect MCP]
    ↓ (Access for SaaS OAuth)
[Cloudflare Zero Trust]
    ↓ (User claims: sub, email)
[MCP Tools] ↔ [Pipedream Connect] ↔ [HubSpot/Xero/PandaDoc]
```

## Step 1: Cloudflare Access Setup

### 1.1 Create Access for SaaS Application

1. Go to [Cloudflare Zero Trust Dashboard](https://one.dash.cloudflare.com/)
2. Navigate to **Applications** → **SaaS**
3. Click **Add an application** → **SaaS**
4. Choose **Custom** application type
5. Configure:
   - **Application name**: `ASI Connect MCP`
   - **Application domain**: Your worker domain (e.g., `asi-mcp.your-account.workers.dev`)

### 1.2 OIDC Configuration (Access for SaaS)

1. In the application settings, note:
   - **Client ID**: Save this as `ACCESS_CLIENT_ID`
   - **Client Secret**: Save this as `ACCESS_CLIENT_SECRET`
2. Set redirect URIs (must exactly match the handler in this repo):
   - Production: `https://asi-mcp.your-account.workers.dev/authorize`
   - Development: `http://localhost:8788/authorize`
3. Record OIDC endpoints (replace `<team>` with your team domain):
   - Authorization URL: `https://<team>.cloudflareaccess.com/oauth2/v2/auth`
   - Token URL: `https://<team>.cloudflareaccess.com/oauth2/v2/token`
   - JWKS URL: `https://<team>.cloudflareaccess.com/oauth2/v2/keys`

4. In Access, add your identity providers and create an allow policy for your users.

### 1.4 Required environment variables

Add the following to your environment (via `wrangler secret put` or your preferred method):

```
# Cloudflare Access (Access for SaaS)
ACCESS_CLIENT_ID
ACCESS_CLIENT_SECRET
ACCESS_AUTHORIZATION_URL   # e.g. https://<team>.cloudflareaccess.com/oauth2/v2/auth
ACCESS_TOKEN_URL           # e.g. https://<team>.cloudflareaccess.com/oauth2/v2/token
ACCESS_JWKS_URL            # e.g. https://<team>.cloudflareaccess.com/oauth2/v2/keys

# OAuthProvider storage
COOKIE_ENCRYPTION_KEY      # random 32+ char secret (used for cookies/HMACs)

# Pipedream Connect
PIPEDREAM_CLIENT_ID
PIPEDREAM_CLIENT_SECRET
PIPEDREAM_PROJECT_ID
PIPEDREAM_ENV              # development | production

# Optional Connect redirect URLs
CONNECT_SUCCESS_REDIRECT
CONNECT_ERROR_REDIRECT
```

### 1.3 Access Policies

1. Go to **Access** → **Applications** → **ASI Connect MCP**
2. Create policies to control who can access:
   - **Include**: Your organization's users
   - **Require**: MFA, device posture, etc. as needed

## Step 2: Pipedream Connect Setup

### 2.1 Create Connect Project

1. Go to [Pipedream Connect](https://pipedream.com/connect)
2. Create a new project: `ASI Connect MCP`
3. Note your **Project ID** (starts with `proj_`)

### 2.2 Configure OAuth Apps

1. Add HubSpot connection:
   - Use your own HubSpot OAuth app
   - Configure scopes: `contacts`, `companies`, `deals`
2. Add Xero connection:
   - Use your own Xero OAuth app
   - Configure scopes: `accounting.read`, `accounting.write`
3. Add PandaDoc connection:
   - Use your own PandaDoc OAuth app
   - Configure scopes as needed

### 2.3 Create API Client

1. Generate Connect API credentials:
   - **Client ID**: Save as `PIPEDREAM_CLIENT_ID`
   - **Client Secret**: Save as `PIPEDREAM_CLIENT_SECRET`
2. Choose environment: `development` or `production`

## Step 3: Deploy the Worker

### 3.1 Create KV Namespaces

```bash
# Create KV namespaces
wrangler kv:namespace create "OAUTH_KV"
wrangler kv:namespace create "USER_LINKS" 
wrangler kv:namespace create "OAUTH_KV" --preview
wrangler kv:namespace create "USER_LINKS" --preview
```

### 3.2 Update Configuration

1. Update `wrangler.jsonc` with the returned KV IDs
2. Copy `.env.example` to `.env` and fill in values
3. Run setup script: `./setup-secrets.sh`

### 3.3 Deploy

```bash
# Deploy to Cloudflare
wrangler deploy
```

## Step 4: Testing the Integration

### 4.1 Test OAuth Flow

1. Connect using an MCP client (e.g., Inspector/Claude Desktop) to the SSE URL `https://your-worker.workers.dev/sse`.
2. The client will open a browser to `.../authorize` and redirect you to Cloudflare Access.
3. Log in with your identity provider and complete the consent.
4. You should be redirected back and the MCP client will receive tokens.

### 4.2 Test MCP Tools

Connect from MCP Inspector or Claude Desktop:

```json
{
  "mcpServers": {
    "asi-connect": {
      "command": "npx",
      "args": [
        "mcp-remote", 
        "https://your-worker.workers.dev/sse"
      ]
    }
  }
}
```

### 4.3 Test Pipedream Integration

1. **Check auth status**:
   ```json
   { "tool": "auth.status", "args": {} }
   ```

2. **Connect HubSpot**:
   ```json
   { "tool": "auth.connect", "args": { "app": "hubspot" } }
   ```

3. **Make authenticated API call**:
   ```json
   {
     "tool": "http.request",
     "args": {
       "method": "GET",
       "url": "https://api.hubapi.com/crm/v3/objects/contacts?limit=5"
     }
   }
   ```

## Step 5: Production Hardening

### 5.1 Access Policies

- Require MFA for all users
- Add device posture checks
- Set up country/IP restrictions if needed

### 5.2 Monitoring

- Enable Worker analytics in Cloudflare dashboard
- Set up alerts for errors or high usage
- Monitor Pipedream Connect usage

### 5.3 Rate Limiting

Consider adding rate limiting to protect against abuse:

```typescript
// Add to your worker
const rateLimiter = new RateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each user to 100 requests per windowMs
});
```

## Troubleshooting

### Common Issues

1. **OAuth redirect mismatch**:
   - Ensure redirect URIs match exactly in Access config
   - Check for HTTP vs HTTPS mismatches

2. **Pipedream Connect errors**:
   - Verify project ID is correct
   - Check API credentials are valid
   - Ensure apps use your own OAuth clients

3. **KV namespace errors**:
   - Verify KV IDs are correct in wrangler.jsonc
   - Check KV namespaces exist in Cloudflare dashboard

4. **CORS issues with MCP clients**:
   - MCP over SSE should handle CORS automatically
   - For HTTP transport, ensure proper headers

### Debug Mode

For local debugging:

```bash
# Run with debug logs
wrangler dev --debug

# Check logs
wrangler tail --debug
```

## Security Considerations

- Never expose raw OAuth credentials to clients
- Use Cloudflare Access policies to restrict access
- Regular rotation of secrets and API keys
- Monitor for unusual usage patterns
- Keep dependencies updated

## Support

- Cloudflare Workers: [Documentation](https://developers.cloudflare.com/workers/)
- Cloudflare Access: [Documentation](https://developers.cloudflare.com/cloudflare-one/)
- Pipedream Connect: [Documentation](https://pipedream.com/docs/connect/)
- MCP Protocol: [Documentation](https://modelcontextprotocol.io/)