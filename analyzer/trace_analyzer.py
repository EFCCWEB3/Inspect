"""
Transaction trace analyzer for EVM chains.

Uses eth_debug_traceTransaction to extract the full call graph of a transaction,
then applies Tarjan's SCC to detect reentrancy cycles.

Supports Ethereum, BSC, and Arbitrum via configurable RPC endpoints.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

from .tarjan import find_cycles, tarjan_scc


# Well-known flash loan function selectors
FLASH_LOAN_SELECTORS = {
    "0xab9c4b5d": "flashLoan (Aave V3)",
    "0x5cffe9de": "flashLoan (Aave V2)",
    "0x920f5c84": "executeOperation (Aave callback)",
    "0xd9c45357": "callFunction (dYdX)",
    "0x10d1e85c": "uniswapV2Call",
    "0xe9cbafb0": "uniswapV3FlashCallback",
    "0x23e30c8b": "onFlashLoan (ERC-3156)",
    "0xfa461e33": "uniswapV3SwapCallback",
}


@dataclass
class CallFrame:
    """A single call within a transaction trace."""
    caller: str
    callee: str
    call_type: str  # CALL, DELEGATECALL, STATICCALL, CREATE, etc.
    value: int = 0
    gas_used: int = 0
    input_data: str = ""
    output_data: str = ""
    depth: int = 0
    children: list[CallFrame] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def selector(self) -> str:
        """Extract the 4-byte function selector from input data."""
        if len(self.input_data) >= 10:
            return self.input_data[:10].lower()
        return ""

    @property
    def is_flash_loan(self) -> bool:
        return self.selector in FLASH_LOAN_SELECTORS

    @property
    def flash_loan_name(self) -> Optional[str]:
        return FLASH_LOAN_SELECTORS.get(self.selector)


@dataclass
class TraceAnalysis:
    """Results of analyzing a transaction trace."""
    tx_hash: str
    chain: str
    call_graph: dict[str, list[str]]
    all_frames: list[CallFrame]
    sccs: list[list[str]]
    cycles: list[list[str]]
    flash_loan_calls: list[dict[str, Any]]
    reentrancy_risk: bool
    flash_loan_detected: bool
    max_call_depth: int
    unique_addresses: set[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tx_hash": self.tx_hash,
            "chain": self.chain,
            "call_graph": self.call_graph,
            "scc_count": len(self.sccs),
            "cycles": self.cycles,
            "cycle_count": len(self.cycles),
            "flash_loan_calls": self.flash_loan_calls,
            "reentrancy_risk": self.reentrancy_risk,
            "flash_loan_detected": self.flash_loan_detected,
            "max_call_depth": self.max_call_depth,
            "unique_addresses": sorted(self.unique_addresses),
            "total_calls": len(self.all_frames),
        }


def fetch_trace(rpc_url: str, tx_hash: str) -> dict[str, Any]:
    """
    Fetch a full transaction trace via debug_traceTransaction.

    Uses the callTracer to get a structured call tree.
    """
    payload = {
        "jsonrpc": "2.0",
        "method": "debug_traceTransaction",
        "params": [tx_hash, {"tracer": "callTracer", "tracerConfig": {"withLog": True}}],
        "id": 1,
    }

    resp = requests.post(rpc_url, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    if "error" in data:
        raise RuntimeError(f"RPC error: {data['error']}")

    return data.get("result", {})


def parse_call_tree(trace: dict[str, Any], depth: int = 0) -> list[CallFrame]:
    """Recursively parse the call tracer output into CallFrame objects."""
    frames: list[CallFrame] = []

    caller = trace.get("from", "").lower()
    callee = trace.get("to", "").lower()
    call_type = trace.get("type", "CALL").upper()

    frame = CallFrame(
        caller=caller,
        callee=callee,
        call_type=call_type,
        value=int(trace.get("value", "0x0"), 16) if trace.get("value") else 0,
        gas_used=int(trace.get("gasUsed", "0x0"), 16) if trace.get("gasUsed") else 0,
        input_data=trace.get("input", ""),
        output_data=trace.get("output", ""),
        depth=depth,
        error=trace.get("error"),
    )
    frames.append(frame)

    for child in trace.get("calls", []):
        child_frames = parse_call_tree(child, depth + 1)
        frame.children = child_frames
        frames.extend(child_frames)

    return frames


def build_call_graph(frames: list[CallFrame]) -> dict[str, list[str]]:
    """
    Build a directed graph (adjacency list) from call frames.

    Edges: caller → callee for each CALL/DELEGATECALL/CALLCODE.
    """
    graph: dict[str, list[str]] = {}

    for frame in frames:
        if not frame.caller or not frame.callee:
            continue
        if frame.caller not in graph:
            graph[frame.caller] = []
        if frame.callee not in graph[frame.caller]:
            graph[frame.caller].append(frame.callee)
        # Ensure all nodes exist in the graph
        if frame.callee not in graph:
            graph[frame.callee] = []

    return graph


def analyze_transaction(rpc_url: str, tx_hash: str, chain: str = "ethereum") -> TraceAnalysis:
    """
    Full analysis pipeline for a single transaction:
    1. Fetch trace via debug_traceTransaction
    2. Parse into call frames
    3. Build call graph
    4. Run Tarjan's SCC to find cycles
    5. Detect flash loan patterns
    """
    trace = fetch_trace(rpc_url, tx_hash)
    frames = parse_call_tree(trace)
    call_graph = build_call_graph(frames)
    sccs = tarjan_scc(call_graph)
    cycles = find_cycles(call_graph)

    flash_loan_calls = []
    for frame in frames:
        if frame.is_flash_loan:
            flash_loan_calls.append({
                "from": frame.caller,
                "to": frame.callee,
                "selector": frame.selector,
                "function": frame.flash_loan_name,
                "value_wei": frame.value,
                "depth": frame.depth,
            })

    unique_addrs = set()
    max_depth = 0
    for frame in frames:
        unique_addrs.add(frame.caller)
        unique_addrs.add(frame.callee)
        max_depth = max(max_depth, frame.depth)
    unique_addrs.discard("")

    return TraceAnalysis(
        tx_hash=tx_hash,
        chain=chain,
        call_graph=call_graph,
        all_frames=frames,
        sccs=sccs,
        cycles=cycles,
        flash_loan_calls=flash_loan_calls,
        reentrancy_risk=len(cycles) > 0,
        flash_loan_detected=len(flash_loan_calls) > 0,
        max_call_depth=max_depth,
        unique_addresses=unique_addrs,
    )


def analyze_bytecode_statically(bytecode_hex: str) -> dict[str, Any]:
    """
    Static analysis of bytecode without requiring a live RPC trace.

    Disassembles the bytecode and looks for vulnerability patterns
    without needing debug_traceTransaction access.
    """
    clean = bytecode_hex.strip()
    if clean.startswith("0x"):
        clean = clean[2:]

    bytecode = bytes.fromhex(clean)
    opcodes = _disassemble_simple(bytecode)

    call_before_sstore = _find_call_before_sstore(opcodes)
    balance_call_pattern = _find_balance_call_pattern(opcodes)
    delegatecall_usage = any(op == 0xF4 for op, _ in opcodes)
    selfdestruct_usage = any(op == 0xFF for op, _ in opcodes)

    return {
        "bytecode_length": len(bytecode),
        "instruction_count": len(opcodes),
        "call_before_sstore_sites": call_before_sstore,
        "balance_call_patterns": balance_call_pattern,
        "uses_delegatecall": delegatecall_usage,
        "uses_selfdestruct": selfdestruct_usage,
        "risk_indicators": _assess_risk(call_before_sstore, balance_call_pattern, delegatecall_usage),
    }


def _disassemble_simple(bytecode: bytes) -> list[tuple[int, int]]:
    """Simple disassembler returning (opcode, offset) pairs."""
    result = []
    i = 0
    while i < len(bytecode):
        op = bytecode[i]
        result.append((op, i))
        # PUSH1..PUSH32 have 1..32 bytes of immediate data
        if 0x60 <= op <= 0x7F:
            i += (op - 0x5F)
        i += 1
    return result


def _find_call_before_sstore(opcodes: list[tuple[int, int]]) -> list[dict[str, int]]:
    """Find CALL/DELEGATECALL opcodes followed by SSTORE without intervening JUMPDEST."""
    results = []
    last_call_offset = None
    last_call_op = None

    for op, offset in opcodes:
        if op in (0xF1, 0xF2, 0xF4):  # CALL, CALLCODE, DELEGATECALL
            last_call_offset = offset
            last_call_op = op
        elif op == 0x55 and last_call_offset is not None:  # SSTORE
            results.append({
                "call_offset": last_call_offset,
                "sstore_offset": offset,
                "call_opcode": last_call_op,
            })
        elif op == 0x5B:  # JUMPDEST — new basic block
            last_call_offset = None
            last_call_op = None

    return results


def _find_balance_call_pattern(opcodes: list[tuple[int, int]]) -> list[dict[str, Any]]:
    """Find BALANCE checks interleaved with CALL — potential flash loan."""
    results = []
    window_balance = 0
    window_calls = 0
    window_start = None

    for op, offset in opcodes:
        if op == 0x31:  # BALANCE
            window_balance += 1
            if window_start is None:
                window_start = offset
        elif op == 0xF1:  # CALL
            window_calls += 1
        elif op == 0x5B:  # JUMPDEST — end window
            if window_balance >= 2 and window_calls >= 2:
                results.append({
                    "start_offset": window_start or 0,
                    "balance_checks": window_balance,
                    "call_count": window_calls,
                })
            window_balance = 0
            window_calls = 0
            window_start = None

    if window_balance >= 2 and window_calls >= 2:
        results.append({
            "start_offset": window_start or 0,
            "balance_checks": window_balance,
            "call_count": window_calls,
        })

    return results


def _assess_risk(
    call_sstore: list[dict[str, int]],
    balance_call: list[dict[str, Any]],
    delegatecall: bool,
) -> dict[str, str]:
    """Produce a risk assessment from static analysis findings."""
    risk = {}

    if call_sstore:
        severity = "HIGH" if any(
            s.get("call_opcode") == 0xF4 for s in call_sstore
        ) else "MEDIUM"
        risk["reentrancy"] = severity

    if balance_call:
        risk["flash_loan"] = "MEDIUM"

    if delegatecall:
        risk["delegatecall_proxy"] = "INFO"

    if not risk:
        risk["overall"] = "LOW"

    return risk


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m analyzer.trace_analyzer <rpc_url> <tx_hash> [chain]")
        print("       python -m analyzer.trace_analyzer --static <bytecode_hex>")
        sys.exit(1)

    if sys.argv[1] == "--static":
        result = analyze_bytecode_statically(sys.argv[2])
        print(json.dumps(result, indent=2, default=str))
    else:
        rpc_url = sys.argv[1]
        tx_hash = sys.argv[2]
        chain = sys.argv[3] if len(sys.argv) > 3 else "ethereum"
        analysis = analyze_transaction(rpc_url, tx_hash, chain)
        print(json.dumps(analysis.to_dict(), indent=2, default=str))
