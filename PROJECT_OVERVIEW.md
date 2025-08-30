## Project Overview

ASI Connect MCP is a production-ready remote MCP (Model Context Protocol) server deployed on Cloudflare Workers. It authenticates users via Cloudflare Zero Trust (Access for SaaS), provides OAuth-protected MCP endpoints, integrates Pipedream Connect for multi-app OAuth and proxying to third-party APIs, and instruments observability with Sentry. It also includes a GitHub-powered SOP search service to guide safe task execution.

- **Entrypoint**: `src/index.ts` exports an `OAuthProvider` that protects MCP routes `"/mcp"` (HTTP) and `"/sse"` (SSE) and registers tools like `auth_status`, `auth_connect`, `auth_disconnect`, `search_apps`, `asi_magic_tool`, `search_sop_docs`, `get_sop_process`, and `send_feedback`.
- **Access flow**: `src/access-handler.ts` implements the `/authorize` UI and completes the OAuth flow using Cloudflare Access for SaaS OIDC.
- **SOP search**: `src/github-sop-search.ts` queries GitHub for SOPs and enriches metadata to guide correct API usage.
- **OAuth helpers**: `src/workers-oauth-utils.ts` contains token/JWT parsing/verification, approval UI, and cookie signing.
- **Configuration**: `wrangler.jsonc`, `tsconfig.json`, `biome.json`; environment bindings include KV (`OAUTH_KV`, `USER_LINKS`), Durable Object (`MCP_OBJECT`), Cloudflare Access secrets, Pipedream Connect credentials, and Sentry.

## High-level Architecture

```mermaid
graph TD
  subgraph Client
    A[MCP Client]
  end

  subgraph Cloudflare
    B[Cloudflare Worker<br/>ASI Connect MCP]
    B1[/mcp HTTP/]:::route
    B2[/sse SSE/]:::route
    K[Durable Object: MCP_OBJECT]
    KV[(KV: OAUTH_KV<br/>KV: USER_LINKS)]
    S[Sentry SDK]
  end

  subgraph Auth
    C[Cloudflare Access<br/>(OIDC for SaaS)]
    D[OAuthProvider<br/>(src/index.ts)]
    E[Access Default Handler<br/>(/authorize UI)]
  end

  subgraph Integrations
    P[Pipedream Connect API]
    APIS[3rd‑party APIs<br/>(HubSpot/Xero/PandaDoc/Gamma...)]
    GH[GitHub API<br/>SOP search]
  end

  A -->|SSE/HTTP| B2
  A -->|HTTP| B1
  B1 --> D
  B2 --> D
  D <-->|OIDC redirect| C
  E -->|completeAuthorization| D
  D -->|KV state| KV
  D -->|Durable state| K
  D -->|tools| P
  D -->|proxy via Connect| APIS
  D -->|SOP search| GH
  D -. observability .-> S

  classDef route fill:#eef,stroke:#88a;
```

## Security Features

- **Zero Trust SSO**: Authentication via Cloudflare Access (OIDC). OAuth flow is mediated by `OAuthProvider`; `/authorize` UI is implemented in `src/access-handler.ts`.
- **OAuth-protected MCP**: MCP endpoints `"/mcp"` and `"/sse"` are protected by the provider; only authenticated clients receive tokens/props.
- **Scoped token handling**: Uses Pipedream Connect per-user `external_user_id` to request scoped API access; never exposes raw 3rd‑party credentials to clients.
- **Header allowlisting**: Proxy sanitization (`sanitizeProxyHeaders`) removes restricted headers and blocks `proxy-*`/`sec-*` to prevent header smuggling.
- **Domain allowlists**: System apps enforce `allowedDomains` for absolute URLs; Pipedream proxy validates app/domain mappings to prevent exfiltration.
- **Secrets hygiene**: Sentry payload scrubbing (`scrubEvent`) redacts auth tokens/secrets; tool arg sanitization removes sensitive fields from breadcrumbs.
- **Cookie security**: Approval cookie is `HttpOnly; Secure; SameSite=Strict` and HMAC‑signed via `signCookie`; TTL‑bounded approvals in KV.
- **KV usage**: Transient state (e.g., OAuth requests, caches) stored in CF KV with TTL; CF provides encryption at rest and TLS in transit.
- **Observability with care**: Sentry instrumentation is resilient and falls back safely; secrets are redacted before send; failures don’t break user flows.
- **Input validation**: `zod` schemas on tool inputs enforce types and bounds; URL normalization/validation paths reduce injection risk.

## ISO/IEC 27001 Alignment (selected, practical mappings)

- **A.9 Access Control**: Zero Trust via Cloudflare Access (SSO, policies, MFA/device posture configurable). OAuthProvider gates MCP routes; least‑privileged per‑app access via Pipedream accounts.
- **A.10 Cryptography**: TLS enforced by Cloudflare. HMAC for cookie integrity. JWKS retrieval supported; token parsing/expiry checks in `verifyToken` with room to extend signature verification.
- **A.12 Operations Security**: Secure header filtering, domain allowlisting, dependency management (npm lock), type checks in CI, and logging/monitoring via Sentry.
- **A.14 System Acquisition, Development, Maintenance**: PR‑based changes, code review, preview deployments, and dependency/code scanning (Dependabot/Code Scanning) support secure SDLC.
- **A.16 Incident Management**: Centralized error and trace capture via Sentry, with user/tool/app tags to accelerate triage; feedback tool creates GitHub issues.
- **A.17 Business Continuity**: Cloudflare Workers provides globally distributed runtime; KV and Durable Objects offer resilient state where used.
- **A.18 Compliance**: Data minimization (no raw third‑party creds exposed), auditability via PR reviews and CI logs. Secrets managed via Cloudflare secrets.

Notes: Organizational controls (policies, risk assessments, asset inventories) are typically handled outside this repo; this service supports technical controls and evidence.

## Secure Development Lifecycle

- **PR‑driven development with code review**: All changes land via GitHub PRs with reviewer approval and branch protections.
- **Preview deployments**: On PR open/update, CI deploys a namespaced Cloudflare Worker (`.github/workflows/preview-deployment.yml`) and comments the preview URL and MCP endpoints for validation.
- **Automated checks**: CI runs install and `npm run type-check` before deploying previews.
- **Cleanup**: On PR close, the preview deployment is deleted (`cleanup-previews.yml`).
- **Dependency and code scanning**: GitHub Dependabot and Code Scanning are used to surface vulnerable dependencies and code issues; renovate/security alerts can be enabled at org/repo level alongside secret scanning.

## Key Endpoints and Tools

- **MCP endpoints**: `"/mcp"` (HTTP), `"/sse"` (SSE)
- **OAuth endpoints**: `"/authorize"`, `"/token"`, `"/register"`
- **Registered tools**: `auth_status`, `auth_connect`, `auth_disconnect`, `search_apps`, `asi_magic_tool`, `search_sop_docs`, `get_sop_process`, `send_feedback`

## Environment Bindings

- **KV**: `OAUTH_KV`, `USER_LINKS`
- **Durable Object**: `MCP_OBJECT`
- **Cloudflare Access**: `ACCESS_CLIENT_ID`, `ACCESS_CLIENT_SECRET`, `ACCESS_AUTHORIZATION_URL`, `ACCESS_TOKEN_URL`, `ACCESS_JWKS_URL`, `COOKIE_ENCRYPTION_KEY`
- **Pipedream Connect**: `PIPEDREAM_CLIENT_ID`, `PIPEDREAM_CLIENT_SECRET`, `PIPEDREAM_PROJECT_ID`, `PIPEDREAM_ENV`
- **Observability**: `SENTRY_DSN`, `SENTRY_ENV`, `CF_VERSION_METADATA`
- **GitHub/SOP**: `GITHUB_TOKEN`, `GITHUB_REPO`, optional `GITHUB_SOP_OWNER/REPO/BRANCH`


