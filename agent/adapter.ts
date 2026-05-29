/**
 * agenc-core integration for the EVM vulnerability detection pipeline.
 *
 * This file documents how the Inspect MCP tools connect to agenc-core.
 * agenc-core is the orchestrator — it runs the daemon, manages agents,
 * calls MCP tools, and talks to Ollama for report generation.
 *
 * Architecture:
 *   Rust bytecode scanner  ─┐
 *   Python graph analyzer  ─┤── MCP tool server (stdio) ── agenc-core ── Ollama
 *   Static analysis        ─┘
 *
 * agenc-core runtime (https://github.com/tetsuo-ai/agenc-core):
 *   - runtime/src/mcp-client/manager.ts   — connects to our MCP server
 *   - runtime/src/llm/providers/ollama/   — talks to Ollama for reasoning
 *   - runtime/src/app-server/agent-cli.ts — runs background agents
 *   - runtime/src/app-server/daemon-cli.ts — manages the daemon lifecycle
 *
 * @module
 */

// ── MCP Server Configuration ──────────────────────────────────────────
// This matches agenc-core's MCPServerConfig interface
// (runtime/src/mcp-client/types.ts:26)

/**
 * MCP server config for agenc-core registration.
 *
 * Register via CLI:
 *   agenc mcp add-json evm-vuln-detector '{"command":"npx","args":["tsx","mcp-server/src/server.ts"]}'
 *
 * Or via config.toml:
 *   [mcp_servers.evm-vuln-detector]
 *   command = "npx"
 *   args = ["tsx", "mcp-server/src/server.ts"]
 */
export const MCP_SERVER_CONFIG = {
  name: "evm-vuln-detector",
  transport: "stdio" as const,
  command: "npx",
  args: ["tsx", "mcp-server/src/server.ts"],
  enabled: true,
  timeout: 30000,
} satisfies McpServerConfigShape;

/** Shape matching agenc-core's McpServerConfig (config/schema.ts:229) */
interface McpServerConfigShape {
  name: string;
  transport?: "stdio" | "sse" | "http" | "websocket" | "ws";
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  enabled?: boolean;
  timeout?: number;
  required?: boolean;
  enabled_tools?: string[];
  disabled_tools?: string[];
}

// ── Ollama Provider Configuration ──────────────────────────────────────
// Matches agenc-core's OllamaProviderConfig
// (runtime/src/llm/providers/ollama/types.ts)

/** Ollama config for agenc-core's provider system. */
export const OLLAMA_CONFIG = {
  host: "http://localhost:11434",
  model: "qwen2.5-coder:7b",
  keepAlive: "5m",
} as const;

// ── Recommended Models ─────────────────────────────────────────────────
// For tool-calling reliability with agenc-core + Ollama:
//   1. qwen2.5-coder:7b  — best small option, most reliable tool calls
//   2. llama3.1:8b        — good general-purpose
//   3. codellama:13b      — larger, better code understanding
//   4. gemma4:e4b         — used by agenc-core's CourtGuard security (see docs/security/)

// ── Usage Examples ─────────────────────────────────────────────────────
//
// 1. Start the daemon:
//    agenc daemon start
//
// 2. Register the MCP server:
//    agenc mcp add-json evm-vuln-detector \
//      '{"command":"npx","args":["tsx","mcp-server/src/server.ts"],"cwd":"/path/to/Inspect"}'
//
// 3. Configure Ollama provider in ~/.agenc/config.toml:
//    [providers.ollama]
//    base_url = "http://localhost:11434"
//    default_model = "qwen2.5-coder:7b"
//
// 4. Run an agent with a vulnerability scanning objective:
//    agenc agent start "scan contract 0x... on ethereum for reentrancy vulnerabilities"
//
// 5. Or use the interactive TUI:
//    agenc --provider ollama --model qwen2.5-coder:7b
//    > scan this contract for flash loan vulnerabilities: 0x...
//
// 6. Run a one-shot scan:
//    agenc --no-tui --provider ollama "analyze transaction 0x... for reentrancy"
//
// The agent will:
//   a) See the MCP tools (scan_bytecode, scan_contract, analyze_trace, static_analysis)
//   b) Choose which tool(s) to call based on your objective
//   c) Pass the structured results to Ollama
//   d) Generate a human-readable vulnerability report
