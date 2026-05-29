"""
Tarjan's Strongly Connected Components algorithm for EVM call graph analysis.

Detects cycles in transaction call graphs — a cycle indicates potential
reentrancy (contract A calls B which calls back into A).

Reference: Tarjan, R.E. (1972) "Depth-first search and linear graph algorithms"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TarjanState:
    """Internal state for Tarjan's algorithm."""
    index_counter: int = 0
    stack: list[str] = field(default_factory=list)
    on_stack: set[str] = field(default_factory=set)
    index: dict[str, int] = field(default_factory=dict)
    lowlink: dict[str, int] = field(default_factory=dict)
    sccs: list[list[str]] = field(default_factory=list)


def tarjan_scc(graph: dict[str, list[str]]) -> list[list[str]]:
    """
    Find all strongly connected components in a directed graph.

    Args:
        graph: Adjacency list {node: [successors]}

    Returns:
        List of SCCs, each SCC is a list of node identifiers.
        SCCs with size > 1 indicate cycles (potential reentrancy).
    """
    state = TarjanState()

    def strongconnect(v: str) -> None:
        state.index[v] = state.index_counter
        state.lowlink[v] = state.index_counter
        state.index_counter += 1
        state.stack.append(v)
        state.on_stack.add(v)

        for w in graph.get(v, []):
            if w not in state.index:
                strongconnect(w)
                state.lowlink[v] = min(state.lowlink[v], state.lowlink[w])
            elif w in state.on_stack:
                state.lowlink[v] = min(state.lowlink[v], state.index[w])

        if state.lowlink[v] == state.index[v]:
            scc: list[str] = []
            while True:
                w = state.stack.pop()
                state.on_stack.discard(w)
                scc.append(w)
                if w == v:
                    break
            state.sccs.append(scc)

    for node in graph:
        if node not in state.index:
            strongconnect(node)

    return state.sccs


def find_cycles(graph: dict[str, list[str]]) -> list[list[str]]:
    """Return only SCCs with size > 1 (actual cycles)."""
    return [scc for scc in tarjan_scc(graph) if len(scc) > 1]
