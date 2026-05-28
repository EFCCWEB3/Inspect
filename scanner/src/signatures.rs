/// Known exploit opcode signatures and Jaccard similarity scoring.
///
/// Each signature is a set of opcode n-grams extracted from known exploit contracts.
/// Bytecode is compared against these signatures using Jaccard similarity:
///   J(A,B) = |A ∩ B| / |A ∪ B|

use std::collections::HashSet;

use crate::opcodes::{disassemble, Instruction, Opcode};

/// An exploit signature: a named pattern with its opcode n-gram set.
#[derive(Debug, Clone)]
pub struct ExploitSignature {
    pub name: &'static str,
    pub category: VulnerabilityClass,
    pub description: &'static str,
    pub ngrams: HashSet<Vec<u8>>,
    pub threshold: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum VulnerabilityClass {
    Reentrancy,
    FlashLoan,
    PriceManipulation,
    AccessControl,
}

impl std::fmt::Display for VulnerabilityClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnerabilityClass::Reentrancy => write!(f, "Reentrancy"),
            VulnerabilityClass::FlashLoan => write!(f, "Flash Loan"),
            VulnerabilityClass::PriceManipulation => write!(f, "Price Manipulation"),
            VulnerabilityClass::AccessControl => write!(f, "Access Control"),
        }
    }
}

/// Extract opcode n-grams of a given window size from bytecode.
pub fn extract_ngrams(bytecode: &[u8], window: usize) -> HashSet<Vec<u8>> {
    let instructions = disassemble(bytecode);
    let raw_opcodes: Vec<u8> = instructions.iter().map(|i| i.raw).collect();
    let mut ngrams = HashSet::new();
    if raw_opcodes.len() >= window {
        for w in raw_opcodes.windows(window) {
            ngrams.insert(w.to_vec());
        }
    }
    ngrams
}

/// Compute Jaccard similarity between two n-gram sets.
pub fn jaccard_similarity(a: &HashSet<Vec<u8>>, b: &HashSet<Vec<u8>>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let intersection = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    intersection / union
}

/// Build the set of known exploit signatures.
pub fn known_signatures() -> Vec<ExploitSignature> {
    vec![
        reentrancy_call_before_sstore(),
        reentrancy_delegatecall_pattern(),
        flash_loan_borrow_repay(),
        flash_loan_callback_pattern(),
        price_manipulation_pattern(),
    ]
}

/// Reentrancy: CALL opcode appears before SSTORE (state update after external call).
/// Pattern: CALL ... SSTORE with no SSTORE before the CALL in the same basic block.
fn reentrancy_call_before_sstore() -> ExploitSignature {
    // Opcode sequence: GAS CALL ... SLOAD ... CALL ... SSTORE
    // This captures the classic reentrancy where state is read, external call is made,
    // then state is updated — allowing the callee to re-enter.
    let pattern: Vec<u8> = vec![
        0x5A, // GAS
        0xF1, // CALL
        0x54, // SLOAD
        0x57, // JUMPI (conditional check)
        0xF1, // CALL (second entry point)
        0x55, // SSTORE (state update AFTER call)
    ];
    let mut ngrams = HashSet::new();
    for w in pattern.windows(3) {
        ngrams.insert(w.to_vec());
    }
    // Also add the critical 2-gram: CALL followed by SSTORE
    ngrams.insert(vec![0xF1, 0x55]);
    // And DELEGATECALL before SSTORE
    ngrams.insert(vec![0xF4, 0x55]);

    ExploitSignature {
        name: "reentrancy_call_before_sstore",
        category: VulnerabilityClass::Reentrancy,
        description: "External CALL precedes SSTORE state update — classic reentrancy vector. \
                      The callee can re-enter before state is committed.",
        ngrams,
        threshold: 0.15,
    }
}

/// Reentrancy via DELEGATECALL — callee executes in caller's storage context.
fn reentrancy_delegatecall_pattern() -> ExploitSignature {
    let pattern: Vec<u8> = vec![
        0x54, // SLOAD
        0xF4, // DELEGATECALL
        0x54, // SLOAD (re-read after delegate)
        0x55, // SSTORE
    ];
    let mut ngrams = HashSet::new();
    for w in pattern.windows(3) {
        ngrams.insert(w.to_vec());
    }
    ngrams.insert(vec![0xF4, 0x54]); // DELEGATECALL then SLOAD
    ngrams.insert(vec![0xF4, 0x55]); // DELEGATECALL then SSTORE

    ExploitSignature {
        name: "reentrancy_delegatecall",
        category: VulnerabilityClass::Reentrancy,
        description: "DELEGATECALL used before state update — callee runs in caller's \
                      storage context, enabling storage manipulation reentrancy.",
        ngrams,
        threshold: 0.12,
    }
}

/// Flash loan: borrow + callback + repay in single transaction.
/// Signature: CALL (borrow) ... CALLDATALOAD ... CALL (repay) with BALANCE checks.
fn flash_loan_borrow_repay() -> ExploitSignature {
    let pattern: Vec<u8> = vec![
        0x31, // BALANCE (check initial balance)
        0xF1, // CALL (borrow from lending pool)
        0x35, // CALLDATALOAD (decode callback params)
        0x31, // BALANCE (check post-borrow balance)
        0xF1, // CALL (execute exploit logic)
        0x31, // BALANCE (verify profit)
        0xF1, // CALL (repay flash loan)
    ];
    let mut ngrams = HashSet::new();
    for w in pattern.windows(3) {
        ngrams.insert(w.to_vec());
    }
    // Key 2-grams for flash loans
    ngrams.insert(vec![0x31, 0xF1]); // BALANCE then CALL
    ngrams.insert(vec![0xF1, 0x31]); // CALL then BALANCE
    ngrams.insert(vec![0xF1, 0x35]); // CALL then CALLDATALOAD

    ExploitSignature {
        name: "flash_loan_borrow_repay",
        category: VulnerabilityClass::FlashLoan,
        description: "Borrow-callback-repay pattern detected. Multiple CALL opcodes \
                      interleaved with BALANCE checks — signature of flash loan usage.",
        ngrams,
        threshold: 0.10,
    }
}

/// Flash loan callback pattern — contract implements a callback that receives
/// borrowed funds and must repay within the same tx.
fn flash_loan_callback_pattern() -> ExploitSignature {
    // Common callback selectors:
    // Aave:     executeOperation(address[],uint256[],uint256[],address,bytes) = 0x920f5c84  (via PUSH4)
    // dYdX:     callFunction(address,(address,uint256),bytes) = 0xd9c45357
    // Uniswap:  uniswapV2Call(address,uint256,uint256,bytes) = 0x10d1e85c
    let pattern: Vec<u8> = vec![
        0x35, // CALLDATALOAD (read function selector)
        0x63, // PUSH4 (callback selector)
        0x14, // EQ (compare selectors)
        0x57, // JUMPI (branch to callback handler)
        0x54, // SLOAD (load state in callback)
        0xF1, // CALL (external interaction during callback)
        0x55, // SSTORE (update state)
    ];
    let mut ngrams = HashSet::new();
    for w in pattern.windows(3) {
        ngrams.insert(w.to_vec());
    }
    // Selector comparison pattern
    ngrams.insert(vec![0x63, 0x14]); // PUSH4 then EQ
    ngrams.insert(vec![0x14, 0x57]); // EQ then JUMPI

    ExploitSignature {
        name: "flash_loan_callback",
        category: VulnerabilityClass::FlashLoan,
        description: "Flash loan callback handler detected. Contract dispatches on known \
                      callback selectors (Aave/dYdX/Uniswap) with state modifications.",
        ngrams,
        threshold: 0.08,
    }
}

/// Price manipulation: reading price from external source then acting on it.
fn price_manipulation_pattern() -> ExploitSignature {
    let pattern: Vec<u8> = vec![
        0xFA, // STATICCALL (read oracle price)
        0x3D, // RETURNDATASIZE
        0x3E, // RETURNDATACOPY
        0x51, // MLOAD (load returned price)
        0x04, // DIV or ratio calc
        0xF1, // CALL (swap/trade based on price)
    ];
    let mut ngrams = HashSet::new();
    for w in pattern.windows(3) {
        ngrams.insert(w.to_vec());
    }
    ngrams.insert(vec![0xFA, 0x3D]); // STATICCALL then RETURNDATASIZE
    ngrams.insert(vec![0x3E, 0x51]); // RETURNDATACOPY then MLOAD

    ExploitSignature {
        name: "price_manipulation",
        category: VulnerabilityClass::PriceManipulation,
        description: "Oracle price read followed by trade execution — potential price \
                      manipulation if oracle can be influenced in same transaction.",
        ngrams,
        threshold: 0.10,
    }
}

/// Result of scanning bytecode against a signature.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanMatch {
    pub signature_name: String,
    pub category: VulnerabilityClass,
    pub description: String,
    pub jaccard_score: f64,
    pub threshold: f64,
    pub matched: bool,
}

/// Scan bytecode against all known signatures, returning matches.
pub fn scan_bytecode(bytecode: &[u8], ngram_window: usize) -> Vec<ScanMatch> {
    let target_ngrams = extract_ngrams(bytecode, ngram_window);
    let signatures = known_signatures();

    signatures
        .iter()
        .map(|sig| {
            let score = jaccard_similarity(&target_ngrams, &sig.ngrams);
            ScanMatch {
                signature_name: sig.name.to_string(),
                category: sig.category,
                description: sig.description.to_string(),
                jaccard_score: score,
                threshold: sig.threshold,
                matched: score >= sig.threshold,
            }
        })
        .collect()
}

/// Structural analysis: detect CALL-before-SSTORE pattern directly in instruction stream.
pub fn detect_call_before_sstore(bytecode: &[u8]) -> Vec<ReentrancyFinding> {
    let instructions = disassemble(bytecode);
    let mut findings = Vec::new();
    let mut last_call_offset: Option<usize> = None;
    let mut last_call_type: Option<&str> = None;
    let mut seen_sstore_since_call = true;

    for instr in &instructions {
        match instr.opcode {
            Opcode::Call | Opcode::CallCode | Opcode::DelegateCall => {
                if !seen_sstore_since_call {
                    // Multiple calls without intermediate SSTORE — suspicious
                }
                last_call_offset = Some(instr.offset);
                last_call_type = Some(match instr.opcode {
                    Opcode::Call => "CALL",
                    Opcode::CallCode => "CALLCODE",
                    Opcode::DelegateCall => "DELEGATECALL",
                    _ => "UNKNOWN",
                });
                seen_sstore_since_call = false;
            }
            Opcode::SStore => {
                if let (Some(call_off), Some(call_name)) = (last_call_offset, last_call_type) {
                    findings.push(ReentrancyFinding {
                        call_offset: call_off,
                        sstore_offset: instr.offset,
                        call_type: call_name.to_string(),
                        severity: if call_name == "DELEGATECALL" {
                            "HIGH"
                        } else {
                            "MEDIUM"
                        }
                        .to_string(),
                    });
                }
                seen_sstore_since_call = true;
            }
            Opcode::JumpDest => {
                // New basic block — reset tracking
                last_call_offset = None;
                last_call_type = None;
                seen_sstore_since_call = true;
            }
            _ => {}
        }
    }

    findings
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReentrancyFinding {
    pub call_offset: usize,
    pub sstore_offset: usize,
    pub call_type: String,
    pub severity: String,
}

/// Detect flash-loan-like patterns: multiple CALL opcodes interleaved with BALANCE checks.
pub fn detect_flash_loan_pattern(bytecode: &[u8]) -> Vec<FlashLoanFinding> {
    let instructions = disassemble(bytecode);
    let mut findings = Vec::new();
    let mut balance_count = 0;
    let mut call_count = 0;
    let mut first_balance_offset: Option<usize> = None;
    let mut call_offsets = Vec::new();

    for instr in &instructions {
        match instr.opcode {
            Opcode::Balance => {
                balance_count += 1;
                if first_balance_offset.is_none() {
                    first_balance_offset = Some(instr.offset);
                }
            }
            Opcode::Call => {
                call_count += 1;
                call_offsets.push(instr.offset);
            }
            Opcode::JumpDest if balance_count >= 2 && call_count >= 2 => {
                // End of a block with multiple BALANCE+CALL — flash loan candidate
                findings.push(FlashLoanFinding {
                    balance_checks: balance_count,
                    external_calls: call_count,
                    first_balance_offset: first_balance_offset.unwrap_or(0),
                    call_offsets: call_offsets.clone(),
                    pattern: "borrow-execute-repay".to_string(),
                });
                balance_count = 0;
                call_count = 0;
                first_balance_offset = None;
                call_offsets.clear();
            }
            _ => {}
        }
    }

    // Check at end of bytecode
    if balance_count >= 2 && call_count >= 2 {
        findings.push(FlashLoanFinding {
            balance_checks: balance_count,
            external_calls: call_count,
            first_balance_offset: first_balance_offset.unwrap_or(0),
            call_offsets,
            pattern: "borrow-execute-repay".to_string(),
        });
    }

    findings
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FlashLoanFinding {
    pub balance_checks: usize,
    pub external_calls: usize,
    pub first_balance_offset: usize,
    pub call_offsets: Vec<usize>,
    pub pattern: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jaccard_identical() {
        let a: HashSet<Vec<u8>> = vec![vec![1, 2], vec![3, 4]].into_iter().collect();
        let score = jaccard_similarity(&a, &a);
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_jaccard_disjoint() {
        let a: HashSet<Vec<u8>> = vec![vec![1, 2]].into_iter().collect();
        let b: HashSet<Vec<u8>> = vec![vec![3, 4]].into_iter().collect();
        let score = jaccard_similarity(&a, &b);
        assert!(score.abs() < f64::EPSILON);
    }

    #[test]
    fn test_jaccard_partial() {
        let a: HashSet<Vec<u8>> = vec![vec![1, 2], vec![3, 4]].into_iter().collect();
        let b: HashSet<Vec<u8>> = vec![vec![1, 2], vec![5, 6]].into_iter().collect();
        let score = jaccard_similarity(&a, &b);
        // Intersection = {[1,2]}, Union = {[1,2],[3,4],[5,6]} → 1/3
        assert!((score - 1.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_detect_call_before_sstore() {
        // Bytecode: PUSH1 0x00 CALL SSTORE
        let bytecode = vec![0x60, 0x00, 0xF1, 0x55];
        let findings = detect_call_before_sstore(&bytecode);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].call_type, "CALL");
    }

    #[test]
    fn test_no_reentrancy_sstore_before_call() {
        // Bytecode: SSTORE CALL — safe order
        let bytecode = vec![0x55, 0xF1];
        let findings = detect_call_before_sstore(&bytecode);
        assert!(findings.is_empty());
    }
}
