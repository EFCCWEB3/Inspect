#!/usr/bin/env bash
# setup-agenc.sh — Wire Inspect vulnerability detection tools into agenc-core.
#
# Prerequisites:
#   - Node.js >= 25.0.0
#   - agenc-core installed (https://github.com/tetsuo-ai/agenc-core)
#   - Ollama installed with qwen2.5-coder:7b pulled
#
# This script:
#   1. Builds the Rust bytecode scanner
#   2. Installs MCP server dependencies
#   3. Registers the MCP server with agenc-core
#   4. Configures the Ollama provider
#   5. Verifies the setup with agenc mcp doctor

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Inspect EVM Vulnerability Detector — agenc-core Setup ==="
echo ""

# ── Step 1: Build the Rust bytecode scanner ───────────────────────────
echo "[1/5] Building Rust bytecode scanner..."
if command -v cargo &>/dev/null; then
  cd "$PROJECT_ROOT/scanner"
  cargo build --release 2>&1
  echo "  ✓ Scanner built: scanner/target/release/evm-scanner"
else
  echo "  ⚠ Rust/cargo not found — scanner will use Python fallback"
fi

# ── Step 2: Install MCP server dependencies ──────────────────────────
echo ""
echo "[2/5] Installing MCP server dependencies..."
cd "$PROJECT_ROOT/mcp-server"
npm install 2>&1
echo "  ✓ MCP server dependencies installed"

# ── Step 3: Install Python analyzer dependencies ─────────────────────
echo ""
echo "[3/5] Installing Python analyzer dependencies..."
pip3 install -r "$PROJECT_ROOT/analyzer/requirements.txt" 2>&1 || true
echo "  ✓ Python analyzer ready"

# ── Step 4: Register MCP server with agenc-core ──────────────────────
echo ""
echo "[4/5] Registering MCP server with agenc-core..."

if command -v agenc &>/dev/null; then
  agenc mcp add-json evm-vuln-detector \
    "{\"command\":\"npx\",\"args\":[\"tsx\",\"$PROJECT_ROOT/mcp-server/src/server.ts\"],\"cwd\":\"$PROJECT_ROOT/mcp-server\"}" \
    --scope user
  echo "  ✓ MCP server registered as 'evm-vuln-detector'"
elif [ -f "$PROJECT_ROOT/../agenc-core/runtime/bin/agenc" ]; then
  node "$PROJECT_ROOT/../agenc-core/runtime/bin/agenc" mcp add-json evm-vuln-detector \
    "{\"command\":\"npx\",\"args\":[\"tsx\",\"$PROJECT_ROOT/mcp-server/src/server.ts\"],\"cwd\":\"$PROJECT_ROOT/mcp-server\"}" \
    --scope user
  echo "  ✓ MCP server registered via local agenc-core"
else
  echo "  ⚠ agenc CLI not found. Register manually:"
  echo "    agenc mcp add-json evm-vuln-detector '\\"
  echo "      {\"command\":\"npx\",\"args\":[\"tsx\",\"$PROJECT_ROOT/mcp-server/src/server.ts\"],\"cwd\":\"$PROJECT_ROOT/mcp-server\"}'"
  echo ""
  echo "  Or add to ~/.agenc/config.toml:"
  echo "    [mcp_servers.evm-vuln-detector]"
  echo "    command = \"npx\""
  echo "    args = [\"tsx\", \"$PROJECT_ROOT/mcp-server/src/server.ts\"]"
  echo "    cwd = \"$PROJECT_ROOT/mcp-server\""
fi

# ── Step 5: Verify setup ─────────────────────────────────────────────
echo ""
echo "[5/5] Verifying setup..."

# Check Ollama
if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
  echo "  ✓ Ollama is running"
  if curl -s http://localhost:11434/api/tags | grep -q "qwen2.5-coder"; then
    echo "  ✓ qwen2.5-coder model available"
  else
    echo "  ⚠ qwen2.5-coder:7b not pulled. Run: ollama pull qwen2.5-coder:7b"
  fi
else
  echo "  ⚠ Ollama not running. Install: curl -fsSL https://ollama.ai/install.sh | sh"
  echo "    Then: ollama serve & ollama pull qwen2.5-coder:7b"
fi

# Check scanner binary
if [ -f "$PROJECT_ROOT/scanner/target/release/evm-scanner" ]; then
  echo "  ✓ Rust scanner binary found"
  # Quick smoke test
  RESULT=$(echo "60006000F155" | "$PROJECT_ROOT/scanner/target/release/evm-scanner" --format json 2>/dev/null)
  if echo "$RESULT" | grep -q "risk_level"; then
    echo "  ✓ Scanner smoke test passed"
  fi
else
  echo "  ⚠ Rust scanner not built (Python fallback will be used)"
fi

# Run agenc mcp doctor if available
if command -v agenc &>/dev/null; then
  echo ""
  agenc mcp doctor evm-vuln-detector 2>/dev/null || true
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Usage:"
echo "  # Start the agenc daemon"
echo "  agenc daemon start"
echo ""
echo "  # Run a vulnerability scan as a background agent"
echo "  agenc agent start 'scan contract 0xdAC17F958D2ee523a2206206994597C13D831ec7 on ethereum for vulnerabilities'"
echo ""
echo "  # Interactive TUI mode"
echo "  agenc --provider ollama --model qwen2.5-coder:7b"
echo ""
echo "  # One-shot scan"
echo "  agenc --no-tui --provider ollama 'analyze this bytecode for reentrancy: 0x6060604052...'"
echo ""
echo "  # Direct scanner CLI (no agenc-core needed)"
echo "  ./scanner/target/release/evm-scanner --rpc <RPC_URL> --address <CONTRACT> --format text"
