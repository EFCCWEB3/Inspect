"""Tests for the Tarjan SCC implementation."""

from analyzer.tarjan import find_cycles, tarjan_scc


def test_no_cycle():
    graph = {"a": ["b"], "b": ["c"], "c": []}
    sccs = tarjan_scc(graph)
    cycles = find_cycles(graph)
    assert len(cycles) == 0
    assert len(sccs) == 3  # each node is its own SCC


def test_simple_cycle():
    graph = {"a": ["b"], "b": ["a"]}
    cycles = find_cycles(graph)
    assert len(cycles) == 1
    assert set(cycles[0]) == {"a", "b"}


def test_reentrancy_cycle():
    """Simulates contract A calling B which calls back into A."""
    graph = {
        "0xcontractA": ["0xcontractB"],
        "0xcontractB": ["0xcontractA"],
    }
    cycles = find_cycles(graph)
    assert len(cycles) == 1
    assert "0xcontractA" in cycles[0]
    assert "0xcontractB" in cycles[0]


def test_complex_graph():
    """Multiple SCCs in a larger graph."""
    graph = {
        "a": ["b"],
        "b": ["c"],
        "c": ["a"],  # cycle: a-b-c
        "d": ["e"],
        "e": ["f"],
        "f": ["d"],  # cycle: d-e-f
        "c": ["a", "d"],  # connects the two cycles
    }
    cycles = find_cycles(graph)
    assert len(cycles) >= 1


def test_self_loop():
    """A self-loop is an SCC of size 1 — Tarjan detects it but find_cycles filters it.
    Use tarjan_scc directly to verify self-loops are found."""
    graph = {"a": ["a"]}
    sccs = tarjan_scc(graph)
    assert len(sccs) == 1
    assert sccs[0] == ["a"]
    # find_cycles filters SCCs of size 1 by design
    cycles = find_cycles(graph)
    assert len(cycles) == 0


def test_flash_loan_graph():
    """
    Simulates a flash loan call graph:
    User → LendingPool → ExploitContract → VictimDEX → LendingPool (repay)
    The cycle: LendingPool ↔ ExploitContract if callback re-enters.
    """
    graph = {
        "user": ["lending_pool"],
        "lending_pool": ["exploit_contract"],
        "exploit_contract": ["victim_dex", "lending_pool"],
        "victim_dex": [],
    }
    cycles = find_cycles(graph)
    assert len(cycles) == 1
    cycle_set = set(cycles[0])
    assert "lending_pool" in cycle_set
    assert "exploit_contract" in cycle_set
