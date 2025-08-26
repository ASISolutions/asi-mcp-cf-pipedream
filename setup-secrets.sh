#!/bin/bash

# Setup script to configure Wrangler secrets for ASI MCP with Cloudflare Access
# Make sure you have the correct values before running this script

echo "Setting up Wrangler secrets for ASI MCP with Cloudflare Access OAuth..."

# Cloudflare Access OAuth configuration
echo "Setting Cloudflare Access OAuth configuration..."
wrangler secret put ACCESS_CLIENT_ID
wrangler secret put ACCESS_CLIENT_SECRET
wrangler secret put ACCESS_AUTHORIZATION_URL
wrangler secret put ACCESS_TOKEN_URL
wrangler secret put ACCESS_JWKS_URL

# Cookie encryption key
echo "Setting cookie encryption key..."
wrangler secret put COOKIE_ENCRYPTION_KEY

# Pipedream Connect
echo "Setting Pipedream Connect configuration..."
wrangler secret put PIPEDREAM_CLIENT_ID
wrangler secret put PIPEDREAM_CLIENT_SECRET
wrangler secret put PIPEDREAM_PROJECT_ID
wrangler secret put PIPEDREAM_ENV

# Optional Connect redirect pages
echo "Setting optional redirect URLs..."
wrangler secret put CONNECT_SUCCESS_REDIRECT
wrangler secret put CONNECT_ERROR_REDIRECT

# GitHub Issues (optional)
echo "Setting GitHub Issues configuration (optional)..."
wrangler secret put GITHUB_TOKEN
wrangler secret put GITHUB_REPO
wrangler secret put GITHUB_API_BASE

echo "All secrets configured!"
echo ""
echo "Don't forget to:"
echo "1. Create KV namespaces:"
echo "   wrangler kv:namespace create 'OAUTH_KV'"
echo "   wrangler kv:namespace create 'USER_LINKS'"
echo "   wrangler kv:namespace create 'OAUTH_KV' --preview"
echo "   wrangler kv:namespace create 'USER_LINKS' --preview"
echo "2. Update wrangler.jsonc with the returned KV namespace IDs"
echo "3. Set up Cloudflare Access for SaaS application"
echo "4. Update your .env file for local development"