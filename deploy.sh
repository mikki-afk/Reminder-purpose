#!/usr/bin/env bash
# One-shot setup + deploy for the Cloudflare Worker.
# Run from the repo root: ./deploy.sh
#
# What it does:
#   1. Verifies wrangler is installed & logged in
#   2. Creates the KV namespace (only first run) and rewrites wrangler.toml
#   3. Prompts for ANTHROPIC_API_KEY / CHAT_PASSWORD if not already set
#   4. Deploys the Worker
#   5. Writes the deployed URL into chat.html
#
# Re-runnable: existing KV / secrets are skipped.

set -e

cd "$(dirname "$0")"
REPO_ROOT="$PWD"
cd worker

# 1. wrangler installed?
if ! command -v wrangler >/dev/null 2>&1; then
  echo "❌ wrangler not found. Install with:  npm install -g wrangler"
  exit 1
fi

# 2. logged in?
if ! wrangler whoami >/dev/null 2>&1; then
  echo "🔑 Not logged in. Running wrangler login (browser will open)…"
  wrangler login
fi

# 3. KV namespace
if grep -q "REPLACE_WITH_YOUR_KV_NAMESPACE_ID" wrangler.toml; then
  echo "📦 Creating KV namespace SUBSCRIPTIONS…"
  KV_OUTPUT="$(wrangler kv namespace create SUBSCRIPTIONS 2>&1 || true)"
  echo "$KV_OUTPUT"
  KV_ID="$(echo "$KV_OUTPUT" | grep -oE 'id ?= ?"[a-f0-9]+"' | head -n1 | sed -E 's/.*"([a-f0-9]+)".*/\1/')"
  if [ -z "$KV_ID" ]; then
    echo "❌ Could not parse KV id from wrangler output. Edit wrangler.toml manually."
    exit 1
  fi
  # macOS / Linux compatible in-place sed
  sed -i.bak "s/REPLACE_WITH_YOUR_KV_NAMESPACE_ID/$KV_ID/" wrangler.toml
  rm -f wrangler.toml.bak
  echo "✅ KV id $KV_ID written to wrangler.toml"
else
  echo "✅ KV namespace already configured"
fi

# 4. Secrets — only prompt if missing
EXISTING_SECRETS="$(wrangler secret list 2>/dev/null || echo '[]')"

ensure_secret() {
  local name="$1"
  local prompt_text="$2"
  local default_value="$3"
  if echo "$EXISTING_SECRETS" | grep -q "\"$name\""; then
    echo "✅ $name already set"
    return
  fi
  local value
  if [ -n "$default_value" ]; then
    read -r -p "$prompt_text [$default_value]: " value
    value="${value:-$default_value}"
  else
    read -r -s -p "$prompt_text: " value
    echo
  fi
  if [ -z "$value" ]; then
    echo "⚠️  empty, skipping $name"
    return
  fi
  printf '%s' "$value" | wrangler secret put "$name"
}

ensure_secret ANTHROPIC_API_KEY "Anthropic API key (sk-ant-…)" ""

# Generate a default password if missing
if ! echo "$EXISTING_SECRETS" | grep -q '"CHAT_PASSWORD"'; then
  GEN_PW="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12 || echo 'changeme123')"
  ensure_secret CHAT_PASSWORD "Chat password (Enter to use the suggested one)" "$GEN_PW"
  echo "🔐 Save this password somewhere — chat.html will ask for it on first use."
else
  echo "✅ CHAT_PASSWORD already set"
fi

# 5. Deploy
echo ""
echo "🚀 Deploying Worker…"
DEPLOY_OUT="$(wrangler deploy 2>&1)"
echo "$DEPLOY_OUT"

WORKER_URL="$(echo "$DEPLOY_OUT" | grep -oE 'https://[a-zA-Z0-9.-]+\.workers\.dev' | head -n1)"
if [ -z "$WORKER_URL" ]; then
  echo "⚠️  Could not auto-detect Worker URL. Update chat.html manually."
  exit 0
fi

# 6. Write URL into chat.html
CHAT_HTML="$REPO_ROOT/chat.html"
if [ -f "$CHAT_HTML" ]; then
  sed -i.bak "s|const WORKER_URL = '[^']*';|const WORKER_URL = '$WORKER_URL';|" "$CHAT_HTML"
  rm -f "$CHAT_HTML.bak"
  echo "✅ chat.html WORKER_URL → $WORKER_URL"
fi

# Same for index.html (it has its own WORKER_URL for push subscriptions)
INDEX_HTML="$REPO_ROOT/index.html"
if [ -f "$INDEX_HTML" ] && grep -q "const WORKER_URL = ''" "$INDEX_HTML"; then
  sed -i.bak "s|const WORKER_URL = '';|const WORKER_URL = '$WORKER_URL';|" "$INDEX_HTML"
  rm -f "$INDEX_HTML.bak"
  echo "✅ index.html WORKER_URL → $WORKER_URL"
fi

echo ""
echo "🎉 Done."
echo ""
echo "Worker: $WORKER_URL"
echo ""
echo "Next:"
echo "  1. Commit the wrangler.toml + chat.html + index.html changes"
echo "  2. Host chat.html (and index.html) on any static service"
echo "     - GitHub Pages: Settings → Pages → Source: main /(root)"
echo "     - Cloudflare Pages: connect this repo, build cmd empty, output /"
echo "  3. Open chat.html, enter the password, chat with Claude."
