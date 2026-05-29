# Inspect — EVM Vulnerability Detection Tool

An EVM bytecode vulnerability scanner and transaction analyzer targeting flash loan attacks, reentrancy, and price manipulation on Ethereum, BSC, and Arbitrum.

## Architecture

```
EVM RPC (eth_subscribe / eth_getCode)
    → Rust bytecode scanner (Jaccard similarity vs known exploit signatures)
    → Python graph analyzer (Tarjan SCC on call graph within tx)
    → MCP tool server (JSON-RPC 2.0 over stdio)
    → agenc-core + Ollama (human-readable vulnerability reports)
```

### Layer 1 — Rust Bytecode Scanner (`scanner/`)

Disassembles EVM bytecode and compares opcode n-grams against known exploit signatures using Jaccard similarity:

```
J(A,B) = |A ∩ B| / |A ∪ B|
```

**Detected patterns:**
- `reentrancy_call_before_sstore` — CALL opcode precedes SSTORE (state update after external call)
- `reentrancy_delegatecall` — DELEGATECALL before state modification
- `flash_loan_borrow_repay` — BALANCE+CALL interleaving (borrow-execute-repay)
- `flash_loan_callback` — Known callback selector dispatch (Aave/dYdX/Uniswap)
- `price_manipulation` — Oracle read (STATICCALL) followed by trade execution

```bash
# Build
cd scanner && cargo build --release

# Scan hex bytecode
echo "0x6060604052..." | ./target/release/evm-scanner --format text

# Scan from RPC
./target/release/evm-scanner \
  --rpc https://eth-mainnet.g.alchemy.com/v2/KEY \
  --address 0xContractAddress \
  --chain ethereum \
  --format json
```

### Layer 2 — Python Graph Analyzer (`analyzer/`)

Uses `debug_traceTransaction` to extract the full call graph of a transaction, then applies **Tarjan's Strongly Connected Components** algorithm to detect reentrancy cycles.

```bash
pip install -r analyzer/requirements.txt

# Analyze a transaction trace
python -m analyzer.trace_analyzer \
  https://eth-mainnet.g.alchemy.com/v2/KEY \
  0xTransactionHash \
  ethereum

# Static analysis (no RPC needed)
python -m analyzer.trace_analyzer --static 0x6060604052...
```

**What it detects:**
- Reentrancy cycles via Tarjan SCC (contract A → B → A)
- Flash loan callback selectors (Aave `executeOperation`, dYdX `callFunction`, Uniswap `uniswapV2Call`)
- Call depth anomalies
- CALL-before-SSTORE patterns (static bytecode analysis)

### Layer 3 — MCP Tool Server (`mcp-server/`)

Exposes scanner and analyzer as MCP tools over JSON-RPC 2.0 via stdio transport.

```bash
cd mcp-server && npm install

# Run the server
npx tsx src/server.ts

# Register with agenc-core (name + JSON config)
agenc mcp add-json evm-vuln-detector \
  '{"command":"npx","args":["tsx","src/server.ts"]}'
```

**Exposed tools:**
| Tool | Description |
|------|-------------|
| `scan_bytecode` | Scan hex bytecode for vulnerability patterns |
| `scan_contract` | Fetch and scan a deployed contract via RPC |
| `analyze_trace` | Full tx trace analysis with Tarjan SCC |
| `static_analysis` | Quick static analysis without RPC |

### Layer 4 — agenc-core + Ollama (`agent/`)

[agenc-core](https://github.com/tetsuo-ai/agenc-core) is the **orchestration and reasoning layer**. It doesn't detect vulnerabilities itself — it coordinates the detection tools via MCP and uses Ollama to interpret and report findings.

```
Your math engines (Rust/Python)   ← Layers 1-2
        ↓
MCP tool server (Layer 3)         ← exposes tools over JSON-RPC 2.0 stdio
        ↓
agenc-core                        ← orchestrator: daemon, agent runtime, MCP client
        ↓
Ollama (local LLM)                ← agenc-core talks to this for reasoning
```

**What agenc-core does:**
- **Runs the daemon** — background process managing agents ([`daemon-cli.ts`](https://github.com/tetsuo-ai/agenc-core/blob/main/runtime/src/app-server/daemon-cli.ts))
- **Runs your agent** — give it an objective in plain English, it calls MCP tools in the right order ([`agent-cli.ts`](https://github.com/tetsuo-ai/agenc-core/blob/main/runtime/src/app-server/agent-cli.ts))
- **Calls your tools via MCP** — sends structured inputs, reads JSON outputs ([`mcp-client/manager.ts`](https://github.com/tetsuo-ai/agenc-core/blob/main/runtime/src/mcp-client/manager.ts))
- **Talks to Ollama** — passes findings to the LLM for human-readable reports ([`ollama/adapter.ts`](https://github.com/tetsuo-ai/agenc-core/blob/main/runtime/src/llm/providers/ollama/adapter.ts))

## Quick Start with agenc-core

```bash
# 1. One-time setup (builds scanner, installs deps, registers MCP server)
./scripts/setup-agenc.sh

# 2. Or manual setup:
# Install Ollama + model
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen2.5-coder:7b

# Register MCP server with agenc-core
agenc mcp add-json evm-vuln-detector \
  '{"command":"npx","args":["tsx","mcp-server/src/server.ts"],"cwd":"/path/to/Inspect/mcp-server"}'

# Configure Ollama in ~/.agenc/config.toml
cat >> ~/.agenc/config.toml << 'EOF'
[providers.ollama]
base_url = "http://localhost:11434"
default_model = "qwen2.5-coder:7b"
EOF

# 3. Start the daemon
agenc daemon start

# 4. Run a vulnerability scan as a background agent
agenc agent start "scan contract 0xdAC17F958D2ee523a2206206994597C13D831ec7 on ethereum for reentrancy"

# 5. Or use the interactive TUI
agenc --provider ollama --model qwen2.5-coder:7b

# 6. Or one-shot mode
agenc --no-tui --provider ollama "analyze this bytecode for flash loans: 0x60006000F155"
```

The standalone Python reporter (`agent/vuln_reporter.py`) also works without agenc-core:

```bash
python -m agent.vuln_reporter scan_results.json [trace_results.json]
python -m agent.vuln_reporter --check-ollama
```

## Inspect Token (INSP)

The `contracts/` directory contains an ERC20 token with voting, delegation, and governance features built using OpenZeppelin.

### Features
- ERC20 Token
- ERC20 Votes (Governance ready)
- ERC20 Permit (Gasless approvals)
- ERC20 Burnable
- AccessControl (Role-based permissions)

### Tech Stack
- Solidity ^0.8.20
- OpenZeppelin Contracts v5.0.0

## Configuration

See `config.json` for chain RPC endpoints, scanner settings, and Ollama configuration.

## Reading List

| Resource | Purpose |
|----------|---------|
| [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) | Labeled historical exploit PoCs — training/test data |
| [pyevmasm](https://github.com/crytic/pyevmasm) | EVM bytecode disassembler reference |
| [eth_debug_traceTransaction](https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-debug#debugtracetransaction) | Full call graph extraction |
| [MCP Tool Server Spec](https://modelcontextprotocol.io/docs/concepts/tools) | MCP tool protocol |
| [Ollama Tool Use](https://ollama.com/blog/tool-support) | Tool-calling models |
| [EVM Opcodes](https://www.evm.codes/) | Complete opcode reference |
| [SWC Registry](https://swcregistry.io/) | Smart Contract Weakness Classification |
| [Rekt.news](https://rekt.news/) | DeFi exploit post-mortems |

## Future Work

- **Fine-tuning:** Requires labeled training data (thousands of vulnerable vs. safe contract examples). Start with prompt-engineered Ollama baseline first.
- **Real-time monitoring:** `eth_subscribe` for pending transactions + mempool scanning
- **Signature expansion:** Import labeled exploits from DeFiHackLabs as new Jaccard signatures
- **Cross-chain:** Extend beyond EVM to Solana BPF and Cosmos CosmWasm
