/**
 * agenc-core adapter for the EVM vulnerability detection pipeline.
 *
 * Connects the MCP tool server to agenc-core so the agent can:
 * 1. Call scan_bytecode / scan_contract to detect vulnerabilities
 * 2. Call analyze_trace to find reentrancy cycles
 * 3. Feed results to Ollama for human-readable reporting
 *
 * Usage with agenc:
 *   agenc mcp add-json '{
 *     "command": "npx",
 *     "args": ["tsx", "mcp-server/src/server.ts"],
 *     "env": {}
 *   }'
 *
 * Then in your agent config, the tools become available as:
 *   - scan_bytecode
 *   - scan_contract
 *   - analyze_trace
 *   - static_analysis
 */

export interface AgencToolConfig {
  command: string;
  args: string[];
  env?: Record<string, string>;
}

export const MCP_SERVER_CONFIG: AgencToolConfig = {
  command: "npx",
  args: ["tsx", "mcp-server/src/server.ts"],
  env: {},
};

/**
 * Example agenc-core workflow for scanning a contract:
 *
 * ```typescript
 * import { Agent } from "agenc-core";
 *
 * const agent = new Agent({
 *   model: "qwen2.5-coder:7b",  // Ollama model
 *   provider: "ollama",
 * });
 *
 * // Add the MCP vulnerability detection tools
 * await agent.mcp.addServer(MCP_SERVER_CONFIG);
 *
 * // Scan a contract
 * const result = await agent.run(
 *   "Scan contract 0x... on Ethereum mainnet for vulnerabilities"
 * );
 * ```
 */
export const AGENT_SYSTEM_PROMPT = `You are an EVM smart contract security auditor with access to
vulnerability detection tools. When asked to analyze a contract or transaction:

1. Use scan_contract or scan_bytecode to check for known vulnerability patterns
2. If a transaction hash is provided, use analyze_trace for call graph analysis
3. Use static_analysis as a quick check when no RPC is available
4. Synthesize findings into a clear security report

Always include:
- Risk rating (CRITICAL/HIGH/MEDIUM/LOW)
- Specific vulnerability locations (opcode offsets)
- Remediation recommendations
- References to known similar exploits`;
