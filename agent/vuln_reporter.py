"""
Vulnerability Report Generator using Ollama.

Takes raw scan/analysis results from the MCP tools and generates
human-readable vulnerability reports using a local Ollama model.

Designed to work with agenc-core: the MCP tools provide structured data,
this module connects to Ollama to produce natural-language explanations.

Recommended models for tool-use reliability:
  - qwen2.5-coder:7b (best small option for tool calling)
  - llama3.1:8b (good general-purpose)
  - codellama:13b (larger, better code understanding)
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Any, Optional

import requests


OLLAMA_BASE_URL = "http://localhost:11434"

SYSTEM_PROMPT = """You are a smart contract security auditor. You analyze EVM bytecode
vulnerability scan results and produce clear, actionable security reports.

When presented with scan data, you should:
1. Explain each finding in plain language
2. Rate the overall risk (CRITICAL / HIGH / MEDIUM / LOW / INFO)
3. Provide specific remediation recommendations
4. Reference relevant EIPs, known exploits, or best practices

Format your response as a structured report with sections:
- Executive Summary
- Findings (numbered, with severity)
- Remediation Steps
- References

Be precise about opcode offsets and Jaccard scores when referencing findings."""

REPORT_TEMPLATE = """## Security Scan Report

**Chain:** {chain}
**Address:** {address}
**Risk Level:** {risk_level}

### Scanner Results
```json
{scanner_json}
```

### Analysis Results
```json
{analyzer_json}
```

Generate a comprehensive security report based on these findings."""


@dataclass
class OllamaConfig:
    base_url: str = OLLAMA_BASE_URL
    model: str = "qwen2.5-coder:7b"
    temperature: float = 0.3
    max_tokens: int = 2048


def check_ollama_available(config: OllamaConfig) -> bool:
    """Check if Ollama is running and the model is available."""
    try:
        resp = requests.get(f"{config.base_url}/api/tags", timeout=5)
        if resp.status_code != 200:
            return False
        models = resp.json().get("models", [])
        model_names = [m.get("name", "") for m in models]
        return any(config.model in name for name in model_names)
    except requests.ConnectionError:
        return False


def generate_report(
    scanner_results: dict[str, Any],
    analyzer_results: Optional[dict[str, Any]] = None,
    config: Optional[OllamaConfig] = None,
) -> str:
    """
    Generate a human-readable vulnerability report using Ollama.

    Args:
        scanner_results: Output from the Rust bytecode scanner
        analyzer_results: Optional output from the Python trace analyzer
        config: Ollama connection configuration

    Returns:
        Formatted vulnerability report string
    """
    if config is None:
        config = OllamaConfig()

    chain = scanner_results.get("chain", "unknown")
    address = scanner_results.get("address", "N/A")
    risk_level = scanner_results.get("risk_level", "UNKNOWN")

    prompt = REPORT_TEMPLATE.format(
        chain=chain,
        address=address,
        risk_level=risk_level,
        scanner_json=json.dumps(scanner_results, indent=2),
        analyzer_json=json.dumps(analyzer_results, indent=2) if analyzer_results else "N/A",
    )

    if not check_ollama_available(config):
        return generate_fallback_report(scanner_results, analyzer_results)

    try:
        resp = requests.post(
            f"{config.base_url}/api/generate",
            json={
                "model": config.model,
                "system": SYSTEM_PROMPT,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": config.temperature,
                    "num_predict": config.max_tokens,
                },
            },
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json().get("response", "Failed to generate report")

    except (requests.ConnectionError, requests.Timeout) as e:
        print(f"Ollama unavailable ({e}), using fallback report generator", file=sys.stderr)
        return generate_fallback_report(scanner_results, analyzer_results)


def generate_fallback_report(
    scanner_results: dict[str, Any],
    analyzer_results: Optional[dict[str, Any]] = None,
) -> str:
    """
    Generate a structured report without Ollama.
    Used as fallback when the LLM is not available.
    """
    lines = []
    lines.append("=" * 60)
    lines.append("EVM VULNERABILITY SCAN REPORT")
    lines.append("=" * 60)
    lines.append("")

    chain = scanner_results.get("chain", "unknown")
    address = scanner_results.get("address", "N/A")
    risk = scanner_results.get("risk_level", "UNKNOWN")
    lines.append(f"Chain:      {chain}")
    lines.append(f"Address:    {address}")
    lines.append(f"Risk Level: {risk}")
    lines.append(f"Bytecode:   {scanner_results.get('bytecode_length', 0)} bytes")
    lines.append(f"Instructions: {scanner_results.get('instruction_count', 0)}")
    lines.append("")

    # Signature matches
    lines.append("--- SIGNATURE MATCHES ---")
    matches = scanner_results.get("signature_matches", [])
    matched = [m for m in matches if m.get("matched")]
    if not matched:
        lines.append("  No known exploit signatures matched.")
    else:
        for i, m in enumerate(matched, 1):
            lines.append(f"  [{i}] {m['signature_name']}")
            lines.append(f"      Category:  {m['category']}")
            lines.append(f"      Jaccard:   {m['jaccard_score']:.4f} (threshold: {m['threshold']:.4f})")
            lines.append(f"      Detail:    {m['description']}")
            lines.append("")

    # Reentrancy findings
    lines.append("--- REENTRANCY ANALYSIS ---")
    reentrancy = scanner_results.get("reentrancy_findings", [])
    if not reentrancy:
        lines.append("  No CALL-before-SSTORE patterns found.")
    else:
        for f in reentrancy:
            lines.append(
                f"  [{f['severity']}] {f['call_type']} at 0x{f['call_offset']:04X} "
                f"-> SSTORE at 0x{f['sstore_offset']:04X}"
            )
    lines.append("")

    # Flash loan findings
    lines.append("--- FLASH LOAN ANALYSIS ---")
    flash = scanner_results.get("flash_loan_findings", [])
    if not flash:
        lines.append("  No flash loan patterns found.")
    else:
        for f in flash:
            lines.append(
                f"  Pattern: {f['pattern']} | "
                f"BALANCE checks: {f['balance_checks']} | "
                f"External CALLs: {f['external_calls']}"
            )
    lines.append("")

    # Trace analysis results (if available)
    if analyzer_results:
        lines.append("--- TRANSACTION TRACE ANALYSIS ---")
        cycles = analyzer_results.get("cycles", [])
        if cycles:
            lines.append(f"  Reentrancy cycles detected: {len(cycles)}")
            for i, cycle in enumerate(cycles, 1):
                lines.append(f"    Cycle {i}: {' -> '.join(cycle)} -> {cycle[0]}")
        else:
            lines.append("  No reentrancy cycles in call graph.")

        fl_calls = analyzer_results.get("flash_loan_calls", [])
        if fl_calls:
            lines.append(f"  Flash loan calls: {len(fl_calls)}")
            for fl in fl_calls:
                lines.append(f"    {fl['function']} from {fl['from'][:10]}... to {fl['to'][:10]}...")

        lines.append(f"  Max call depth: {analyzer_results.get('max_call_depth', 0)}")
        lines.append(f"  Unique addresses: {len(analyzer_results.get('unique_addresses', []))}")
    lines.append("")

    # Remediation
    lines.append("--- REMEDIATION ---")
    if matched or reentrancy:
        lines.append("  1. Apply checks-effects-interactions pattern")
        lines.append("  2. Use OpenZeppelin ReentrancyGuard (nonReentrant modifier)")
        lines.append("  3. Avoid state changes after external calls")
        if any(m.get("category") == "FlashLoan" for m in matched) or flash:
            lines.append("  4. Implement flash loan access controls")
            lines.append("  5. Use time-weighted average prices (TWAP) for oracle reads")
    else:
        lines.append("  No critical remediations needed based on scan results.")

    lines.append("")
    lines.append("--- REFERENCES ---")
    lines.append("  - SWC-107: Reentrancy (https://swcregistry.io/docs/SWC-107)")
    lines.append("  - EIP-3156: Flash Loans (https://eips.ethereum.org/EIPS/eip-3156)")
    lines.append("  - DeFiHackLabs: https://github.com/SunWeb3Sec/DeFiHackLabs")
    lines.append("  - Rekt.news: https://rekt.news")
    lines.append("")
    lines.append(f"Summary: {scanner_results.get('summary', 'N/A')}")
    lines.append("=" * 60)

    return "\n".join(lines)


def generate_report_from_mcp(mcp_tool_output: str, config: Optional[OllamaConfig] = None) -> str:
    """
    Convenience wrapper: parse MCP tool JSON output and generate report.
    This is the function agenc-core would call after invoking the MCP tools.
    """
    try:
        data = json.loads(mcp_tool_output)
    except json.JSONDecodeError:
        return f"Error: Could not parse MCP tool output as JSON:\n{mcp_tool_output[:500]}"

    return generate_report(data, config=config)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m agent.vuln_reporter <scan_results.json> [trace_results.json]")
        print("       python -m agent.vuln_reporter --check-ollama")
        sys.exit(1)

    if sys.argv[1] == "--check-ollama":
        cfg = OllamaConfig()
        if check_ollama_available(cfg):
            print(f"Ollama available with model {cfg.model}")
        else:
            print(f"Ollama not available at {cfg.base_url} or model {cfg.model} not found")
            print("Install: curl -fsSL https://ollama.ai/install.sh | sh")
            print(f"Then: ollama pull {cfg.model}")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        scanner_data = json.load(f)

    analyzer_data = None
    if len(sys.argv) > 2:
        with open(sys.argv[2]) as f:
            analyzer_data = json.load(f)

    report = generate_report(scanner_data, analyzer_data)
    print(report)
