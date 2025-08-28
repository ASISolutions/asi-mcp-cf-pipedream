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

### MCP Tools Available

1. **`auth_status`** - Check authentication status for connected apps
2. **`auth_connect`** - Generate Pipedream Connect Links for OAuth
3. **`auth_disconnect`** - Remove stored credentials for apps
4. **`auth_apps`** - List available apps with proxy support
5. **`proxy_request`** - Make authenticated requests through Pipedream proxy
6. **`send_feedback`** - Create GitHub issues for user feedback
7. **`search_sop_docs`** - Search ASI Solutions SOP documentation on GitHub
8. **`get_sop_process`** - Get specific SOP process by process code

### Authentication Flow

1. MCP client initiates OAuth with `/authorize`
2. Server redirects to Cloudflare Access for authentication
3. Access returns with user claims (sub, email, name)
4. Server completes OAuth flow and issues tokens
5. MCP tools use the authenticated user context for API calls

### API Integration Patterns

**Pipedream Connect Apps:**
- Dynamic discovery through Pipedream apps API
- Proxy-based requests with automatic token injection
- Support for both static and dynamic app configurations
- Host-to-app resolution from URL patterns

**System Apps (Direct Auth):**
- Hard-coded configuration for apps with API key auth
- Direct HTTP requests with credential injection
- Currently supports Gamma app as example

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
- `GITHUB_SOP_OWNER` - Owner of SOP docs repository (defaults to "asi-solutions")
- `GITHUB_SOP_REPO` - Name of SOP docs repository (defaults to "sop-docs")  
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
4. The `proxy_request` tool will automatically handle routing

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