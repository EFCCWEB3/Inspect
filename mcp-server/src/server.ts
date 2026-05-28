/**
 * MCP Tool Server for EVM Vulnerability Detection
 *
 * Exposes the bytecode scanner and trace analyzer as MCP tools
 * over JSON-RPC 2.0 via stdio transport.
 *
 * Tools:
 *   - scan_bytecode: Scan hex bytecode for vulnerability patterns
 *   - scan_contract: Fetch and scan a deployed contract via RPC
 *   - analyze_trace: Analyze a transaction trace for reentrancy/flash loans
 *   - static_analysis: Run static analysis on bytecode without RPC trace
 *
 * Usage:
 *   npx tsx src/server.ts
 *   agenc mcp add-json '{"command":"npx","args":["tsx","src/server.ts"]}'
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execSync } from "node:child_process";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "../..");

const server = new McpServer({
  name: "evm-vuln-detector",
  version: "1.0.0",
});

// -------------------------------------------------------------------
// Tool 1: scan_bytecode — run Rust scanner on raw bytecode
// -------------------------------------------------------------------
server.tool(
  "scan_bytecode",
  "Scan EVM bytecode for vulnerability patterns (reentrancy, flash loan, price manipulation) using Jaccard similarity against known exploit signatures.",
  {
    bytecode: z.string().describe("Hex-encoded EVM bytecode (with or without 0x prefix)"),
    chain: z.string().default("ethereum").describe("Chain name for context (ethereum, bsc, arbitrum)"),
    format: z.enum(["json", "text"]).default("json").describe("Output format"),
    ngram_window: z.number().default(3).describe("N-gram window size for Jaccard comparison"),
  },
  async ({ bytecode, chain, format, ngram_window }) => {
    try {
      const scannerBin = path.join(PROJECT_ROOT, "scanner/target/release/evm-scanner");
      const args = [
        "--bytecode", bytecode,
        "--chain", chain,
        "--format", format,
        "--ngram-window", String(ngram_window),
      ];

      const result = execSync(`${scannerBin} ${args.join(" ")}`, {
        encoding: "utf-8",
        timeout: 30000,
      });

      return {
        content: [{ type: "text" as const, text: result }],
      };
    } catch (error) {
      // Fallback to Python static analysis if Rust binary not built
      return runPythonStaticAnalysis(bytecode);
    }
  }
);

// -------------------------------------------------------------------
// Tool 2: scan_contract — fetch bytecode from RPC and scan
// -------------------------------------------------------------------
server.tool(
  "scan_contract",
  "Fetch deployed contract bytecode from an EVM RPC endpoint and scan for vulnerabilities.",
  {
    rpc_url: z.string().url().describe("EVM JSON-RPC endpoint URL"),
    address: z.string().describe("Contract address (0x...)"),
    chain: z.string().default("ethereum").describe("Chain name (ethereum, bsc, arbitrum)"),
  },
  async ({ rpc_url, address, chain }) => {
    try {
      const scannerBin = path.join(PROJECT_ROOT, "scanner/target/release/evm-scanner");
      const args = [
        "--rpc", rpc_url,
        "--address", address,
        "--chain", chain,
        "--format", "json",
      ];

      const result = execSync(`${scannerBin} ${args.join(" ")}`, {
        encoding: "utf-8",
        timeout: 30000,
      });

      return {
        content: [{ type: "text" as const, text: result }],
      };
    } catch (error) {
      // Fallback: fetch bytecode via curl and use Python
      return fetchAndAnalyze(rpc_url, address, chain);
    }
  }
);

// -------------------------------------------------------------------
// Tool 3: analyze_trace — full tx trace analysis via debug_traceTransaction
// -------------------------------------------------------------------
server.tool(
  "analyze_trace",
  "Analyze a transaction's call graph using debug_traceTransaction. Runs Tarjan's SCC algorithm to detect reentrancy cycles and identifies flash loan callbacks.",
  {
    rpc_url: z.string().url().describe("EVM JSON-RPC endpoint with debug_traceTransaction support"),
    tx_hash: z.string().describe("Transaction hash to analyze"),
    chain: z.string().default("ethereum").describe("Chain name"),
  },
  async ({ rpc_url, tx_hash, chain }) => {
    try {
      const analyzerPath = path.join(PROJECT_ROOT, "analyzer");
      const cmd = `cd "${PROJECT_ROOT}" && python3 -m analyzer.trace_analyzer "${rpc_url}" "${tx_hash}" "${chain}"`;
      const result = execSync(cmd, {
        encoding: "utf-8",
        timeout: 60000,
      });

      return {
        content: [{ type: "text" as const, text: result }],
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({
          error: "Trace analysis failed",
          detail: msg,
          hint: "Ensure the RPC endpoint supports debug_traceTransaction (requires archive node).",
        }) }],
        isError: true,
      };
    }
  }
);

// -------------------------------------------------------------------
// Tool 4: static_analysis — Python-based static analysis (no RPC needed)
// -------------------------------------------------------------------
server.tool(
  "static_analysis",
  "Run static vulnerability analysis on EVM bytecode without requiring an RPC endpoint. Detects CALL-before-SSTORE reentrancy patterns and flash loan signatures.",
  {
    bytecode: z.string().describe("Hex-encoded EVM bytecode"),
  },
  async ({ bytecode }) => {
    return runPythonStaticAnalysis(bytecode);
  }
);

// -------------------------------------------------------------------
// Helper: Run Python static analysis
// -------------------------------------------------------------------
async function runPythonStaticAnalysis(bytecode: string) {
  try {
    const cmd = `cd "${PROJECT_ROOT}" && python3 -m analyzer.trace_analyzer --static "${bytecode}"`;
    const result = execSync(cmd, {
      encoding: "utf-8",
      timeout: 30000,
    });
    return {
      content: [{ type: "text" as const, text: result }],
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text" as const, text: JSON.stringify({
        error: "Static analysis failed",
        detail: msg,
      }) }],
      isError: true,
    };
  }
}

// -------------------------------------------------------------------
// Helper: Fetch bytecode via RPC and analyze with Python
// -------------------------------------------------------------------
async function fetchAndAnalyze(rpcUrl: string, address: string, chain: string) {
  try {
    const payload = JSON.stringify({
      jsonrpc: "2.0",
      method: "eth_getCode",
      params: [address, "latest"],
      id: 1,
    });

    const curlResult = execSync(
      `curl -s -X POST -H "Content-Type: application/json" -d '${payload}' "${rpcUrl}"`,
      { encoding: "utf-8", timeout: 15000 }
    );

    const rpcResp = JSON.parse(curlResult);
    const code = rpcResp.result;

    if (!code || code === "0x" || code === "0x0") {
      return {
        content: [{ type: "text" as const, text: JSON.stringify({
          error: "No code at address",
          address,
          chain,
        }) }],
        isError: true,
      };
    }

    return runPythonStaticAnalysis(code);
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text" as const, text: JSON.stringify({
        error: "Failed to fetch and analyze contract",
        detail: msg,
      }) }],
      isError: true,
    };
  }
}

// -------------------------------------------------------------------
// Start the server
// -------------------------------------------------------------------
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("EVM Vulnerability Detection MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
