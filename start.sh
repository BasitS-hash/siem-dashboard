#!/usr/bin/env bash
# SentinelView — quick launch script
# Works even when node/npm are not on system PATH

set -e

# Prefer system node if available, fall back to local install
if command -v node &>/dev/null; then
  export NODE_BIN=$(command -v node)
  export NPM_BIN=$(command -v npm)
else
  LOCAL_NODE="$HOME/node-local/bin"
  if [ -f "$LOCAL_NODE/node" ]; then
    export PATH="$LOCAL_NODE:$PATH"
  else
    echo "[!] Node.js not found. Installing locally..."
    ARCH=$(uname -m)
    if [ "$ARCH" = "arm64" ]; then
      URL="https://nodejs.org/dist/v20.18.3/node-v20.18.3-darwin-arm64.tar.gz"
    else
      URL="https://nodejs.org/dist/v20.18.3/node-v20.18.3-darwin-x64.tar.gz"
    fi
    mkdir -p "$HOME/node-local"
    curl -fsSL "$URL" | tar -xz -C "$HOME/node-local" --strip-components=1
    export PATH="$HOME/node-local/bin:$PATH"
  fi
fi

echo "[*] Node $(node --version) / npm $(npm --version)"

# Install deps if needed
if [ ! -d "node_modules" ]; then
  echo "[*] Installing dependencies..."
  npm install
fi

echo ""
echo "  Frontend: http://localhost:5200"
echo "  Backend:  http://localhost:3001"
echo ""

# Run both concurrently
npm run dev
