# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an ASI Connect MCP Server - a production-ready remote MCP (Model Context Protocol) server that runs on Cloudflare Workers. It provides OAuth-protected access to multiple APIs through Pipedream Connect and direct system app authentication.

**Key Technologies:**
- Cloudflare Workers with TypeScript
- Model Context Protocol (MCP) SDK
- Pipedream Connect for OAuth management
- Cloudflare Access for SSO authentication
- KV storage for caching and state

## Common Development Commands

### Development & Testing
```bash
npm run dev          # Start local development server on port 8788
npm run start        # Alias for dev
wrangler dev         # Direct wrangler command
```

### Code Quality
```bash
npm run format       # Format code with Biome
npm run lint:fix     # Fix linting issues with Biome
npm run type-check   # TypeScript type checking
```

### Deployment
```bash
npm run deploy       # Deploy to Cloudflare Workers
npm run cf-typegen   # Generate Cloudflare Worker types
```

### Local Development URLs
- MCP SSE endpoint: `http://localhost:8788/sse`
- OAuth authorize: `http://localhost:8788/authorize`

## Architecture Overview

### Core Components

1. **OAuth Provider Wrapper** (`src/index.ts`):
   - Wraps the MCP server with Cloudflare's OAuth Provider
   - Integrates with Cloudflare Access for SSO
   - Handles authentication flow and token management

2. **MCP Server Class** (`ASIConnectMCP`):
   - Extends `McpAgent` from the agents library
   - Implements MCP tools for authentication and API requests
   - Manages user sessions and external service integrations

3. **Access Handler** (`src/access-handler.ts`):
   - Handles the OAuth authorization flow
   - Integrates with Cloudflare Access as upstream OAuth provider
   - Manages client registration and token exchange

4. **OAuth Utils** (`src/workers-oauth-utils.ts`):
   - JWT parsing and verification utilities
   - Cookie signing and security helpers
   - Upstream OAuth token exchange functions

5. **URL Access Policy Engine** (`src/index.ts`):
   - KV-backed policy system for fine-grained access control
   - Multi-dimensional gating by user, app, method, host, and path
   - Runtime policy updates without deployment
   - Deny-overrides-allow security model with structured error responses

### MCP Tools Available

1. **`auth_status`** - Check authentication status for connected apps
2. **`search_apps`** - Search and discover available Pipedream Connect apps by name, slug, description, or domain. **Use this tool first** when a user wants to connect to a service (e.g., "connect me to xero" → search for "xero" → use returned `appSlug` with `auth_connect`)
3. **`auth_connect`** - Generate Pipedream Connect Links for OAuth (requires exact `appSlug` from `search_apps`)
4. **`auth_disconnect`** - Remove stored credentials for apps
5. **`asi_magic_tool`** - Make authenticated requests through Pipedream proxy or direct system APIs. **CRITICAL: Always search and review SOPs using `search_sop_docs` before using this tool to ensure proper procedures are followed.** All requests are subject to the URL Access Policy system for security enforcement.
6. **`send_feedback`** - Create GitHub issues for user feedback
7. **`search_sop_docs`** - Search ASI Solutions SOP documentation on GitHub. **Use this tool before making any API requests with `asi_magic_tool` to understand proper procedures and workflows.**
8. **`get_sop_process`** - Get specific SOP process by process code

### Authentication Flow

1. MCP client initiates OAuth with `/authorize`
2. Server redirects to Cloudflare Access for authentication
3. Access returns with user claims (sub, email, name)
4. Server completes OAuth flow and issues tokens
5. MCP tools use the authenticated user context for API calls

### API Integration Patterns

**App Discovery and Connection Flow:**
1. User requests connection: "connect me to xero"
2. LLM calls `search_apps` with query "xero"  
3. LLM finds matching app (e.g., `xero_accounting_api`)
4. LLM calls `auth_connect` with the exact `appSlug`
5. User follows the OAuth flow via the returned URL

**Pipedream Connect Apps:**
- Dynamic discovery through Pipedream apps API via `search_apps`
- Proxy-based requests with automatic token injection
- Support for both static and dynamic app configurations
- Host-to-app resolution from URL patterns

**System Apps (Direct Auth):**
- Hard-coded configuration for apps with API key auth
- Direct HTTP requests with credential injection
- Currently supports Gamma app as example

## URL Access Policy System

The MCP server includes a comprehensive policy engine that controls API access based on user identity, application, HTTP method, host patterns, and path patterns. This provides fine-grained security controls over all API requests made through the `asi_magic_tool`.

### Policy Architecture

**Policy Storage:**
- Policies are stored in the `USER_LINKS` KV namespace at key `mcp:policy:v1`
- 60-second in-memory caching for performance
- Runtime updates without requiring code deployment

**Policy Evaluation:**
- All `asi_magic_tool` requests are evaluated against the policy before execution
- Three enforcement points: explicit system apps, preferred system apps, and Pipedream proxy requests
- Deny rules always override allow rules (security-first approach)
- Falls back to `defaultMode` if no explicit rules match

**Policy Structure:**
```typescript
interface PolicyDocument {
  version: string;                    // Policy version for tracking
  defaultMode: "allow" | "deny";      // Global default behavior
  appDefaults?: Record<string, "allow" | "deny">; // Per-app defaults
  rules: PolicyRule[];               // Explicit allow/deny rules
}

interface PolicyRule {
  id?: string;                       // Unique rule identifier
  description?: string;              // Human-readable description
  effect: "allow" | "deny";          // Rule action
  subjects?: {                       // User/group targeting
    users?: string[];                // Match by sub or email claims
    groups?: string[];               // Match by Cloudflare Access groups
  };
  providers?: ("system" | "pipedream" | "*")[]; // Provider filtering
  apps?: string[];                   // App slug filtering (supports wildcards)
  methods?: ("GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "*")[]; 
  hosts?: string[];                  // Host pattern matching (supports wildcards)
  paths?: string[];                  // Path pattern matching (supports wildcards)
}
```

### Current Policy Configuration

The current policy follows these rules:

**Default Behavior:**
- `defaultMode: "allow"` - All requests allowed unless explicitly blocked

**Restricted Apps (GET-only):**
- **NetSuite**: Only GET requests permitted
- **Marketo**: Only GET requests permitted
- **Autotask**: Only GET requests permitted
- **Cloudflare**: Only GET requests permitted

**Xero Special Rules:**
- **Contacts** (`/api.xro/2.0/contacts/**`): Full CRUD operations allowed
- **Purchase Orders** (`/api.xro/2.0/purchaseorders/**`): Full CRUD operations allowed
- **All other endpoints**: GET-only (POST/PUT/PATCH/DELETE blocked)

### Policy Management Commands

**View Current Policy:**
```bash
npx wrangler kv key get --binding=USER_LINKS "mcp:policy:v1" --preview false
```

**Update Policy:**
```bash
# 1. Edit your policy file (e.g., policy.json)
# 2. Upload to KV storage
npx wrangler kv key put --binding=USER_LINKS "mcp:policy:v1" --path=policy.json --preview false
```

**Example Policy Update:**
```bash
cat > new-policy.json << 'EOF'
{
  "version": "2025-08-30-v3",
  "defaultMode": "allow",
  "rules": [
    {
      "id": "block-delete-everywhere",
      "description": "Never allow DELETE operations",
      "effect": "deny",
      "methods": ["DELETE"]
    },
    {
      "id": "engineering-full-access",
      "description": "Engineering group gets full access",
      "effect": "allow",
      "subjects": { "groups": ["Engineering"] },
      "methods": ["*"]
    }
  ]
}
EOF

npx wrangler kv key put --binding=USER_LINKS "mcp:policy:v1" --path=new-policy.json --preview false
```

### Wildcard Pattern Matching

**Supported Wildcards:**
- `*` - Matches any characters except `/` (single path segment)
- `**` - Matches any characters including `/` (multiple path segments)
- `?` - Matches any single character

**Examples:**
- `api.*.com` - Matches `api.example.com`, `api.test.com`
- `/v1/**` - Matches `/v1/users`, `/v1/orders/123/items`
- `/users/?/profile` - Matches `/users/1/profile`, `/users/a/profile`

**Security Features:**
- Input length limited to 200 characters
- Character validation (alphanumeric + safe symbols only)
- Non-greedy regex quantifiers prevent ReDoS attacks
- Invalid patterns fail safely (deny access)

### Policy Debugging

**Blocked Request Response:**
When a request is blocked by policy, the response includes detailed information:
```json
{
  "error": "blocked_by_policy",
  "message": "This request was blocked by policy.",
  "reason": "Matched explicit deny rule",
  "matched_rule": {
    "id": "no-delete-everywhere",
    "effect": "deny",
    "methods": ["DELETE"]
  },
  "context": {
    "provider": "pipedream",
    "app": "hubspot",
    "method": "DELETE",
    "host": "api.hubapi.com", 
    "path": "/crm/v3/objects/contacts/123"
  }
}
```

**Policy Evaluation Order:**
1. **Subject matching**: Check if rule applies to user/groups
2. **Context matching**: Check provider, app, method, host, path
3. **Effect precedence**: Deny rules override allow rules
4. **Fallback**: Use app default or global `defaultMode`

### Best Practices

**Policy Design:**
- Start with `defaultMode: "deny"` for high-security environments
- Use descriptive rule IDs and descriptions for maintainability
- Test policy changes in development environment first
- Version your policies for rollback capability

**Security Considerations:**
- Review policies regularly, especially after app additions
- Monitor blocked requests through structured error responses  
- Use group-based rules rather than individual user rules when possible
- Keep wildcard patterns simple to avoid performance issues

**Operational Guidelines:**
- Policies take effect within 60 seconds (cache TTL)
- No deployment required for policy updates
- Changes are immediately visible in KV storage
- Backup policies before making significant changes

## Configuration Files

- **`wrangler.jsonc`** - Cloudflare Workers configuration with KV bindings
- **`biome.json`** - Code formatting and linting rules
- **`tsconfig.json`** - TypeScript compilation settings
- **`package.json`** - Dependencies and npm scripts

## Environment Variables (Secrets)

### Cloudflare Access OAuth
- `ACCESS_CLIENT_ID` - Client ID from Access for SaaS app
- `ACCESS_CLIENT_SECRET` - Client secret from Access
- `ACCESS_AUTHORIZATION_URL` - Access OAuth authorize endpoint
- `ACCESS_TOKEN_URL` - Access OAuth token endpoint  
- `ACCESS_JWKS_URL` - Access JWKS endpoint for token verification
- `COOKIE_ENCRYPTION_KEY` - Key for cookie signing (generate with `openssl rand -hex 32`)

### Pipedream Connect
- `PIPEDREAM_CLIENT_ID` - Connect API client ID
- `PIPEDREAM_CLIENT_SECRET` - Connect API client secret
- `PIPEDREAM_PROJECT_ID` - Connect project ID (proj_xxx format)
- `PIPEDREAM_ENV` - Environment ("development" or "production")

### Optional Features
- `CONNECT_SUCCESS_REDIRECT` - Redirect after successful OAuth
- `CONNECT_ERROR_REDIRECT` - Redirect after OAuth error
- `GITHUB_TOKEN` - GitHub token for feedback issues and SOP documentation access
- `GITHUB_REPO` - GitHub repo for feedback (owner/repo format)
- `GAMMA_API_KEY` - API key for Gamma system app

### GitHub SOP Documentation
- `GITHUB_SOP_OWNER` - Owner of SOP docs repository (defaults to "ASISolutions")
- `GITHUB_SOP_REPO` - Name of SOP docs repository (defaults to "docs")  
- `GITHUB_SOP_BRANCH` - Branch of SOP docs repository (defaults to "main")

## Development Patterns

### Adding New MCP Tools
1. Add tool definition in `ASIConnectMCP.init()` method
2. Use `this.server.tool(name, schema, handler)` pattern
3. Access user context with `this.getExternalUserId()`
4. Return structured responses with `content` array

### Adding New System Apps
1. Extend `getSystemAppsConfig()` in `src/index.ts`
2. Define allowed domains, base URL, and auth configuration
3. Add environment variable for API credentials
4. The `asi_magic_tool` will automatically handle routing

### Error Handling
- Use structured error responses with `error` field
- Include helpful context like `supported_apps` or `allowed_domains`  
- Provide actionable guidance in error messages
- Use GitHub feedback tool for user-reported issues

### Testing Considerations
- Use `wrangler dev` for local development
- Test OAuth flow with MCP Inspector or AI Playground
- Verify KV storage operations work correctly
- Test both Pipedream proxy and direct system app requests
- **Test policy enforcement** by making requests that should be blocked/allowed
- Monitor structured error responses for policy debugging
- Verify policy cache invalidation (60-second TTL) after updates

## Key Files to Modify

- `src/index.ts` - Main server logic, MCP tools, app configurations
- `src/access-handler.ts` - OAuth flow customizations
- `wrangler.jsonc` - Worker configuration, KV bindings, secrets
- `package.json` - Dependencies and build scripts

## Common Issues

1. **KV Namespace IDs** - Must match between `wrangler.jsonc` and actual Cloudflare KV namespaces
2. **OAuth Redirect URIs** - Must be registered in both Cloudflare Access and MCP client
3. **CORS Headers** - Handled automatically by the MCP SDK for SSE transport
4. **Token Expiration** - Pipedream handles OAuth refresh; Access tokens are validated per request
5. **Policy Not Taking Effect** - Wait 60 seconds for cache invalidation, verify KV key `mcp:policy:v1` exists
6. **Unexpected Policy Blocks** - Check rule precedence (deny overrides allow), verify app slug matching
7. **Wildcard Patterns Not Matching** - Ensure patterns use correct syntax (`*` vs `**`), check for typos in paths/hosts
8. **Policy JSON Invalid** - Validate JSON syntax before uploading, check required fields (`version`, `defaultMode`, `rules`)