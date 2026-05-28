mod opcodes;
mod signatures;

use clap::Parser;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

use opcodes::disassemble;
use signatures::{
    detect_call_before_sstore, detect_flash_loan_pattern, scan_bytecode, FlashLoanFinding,
    ReentrancyFinding, ScanMatch,
};

#[derive(Parser)]
#[command(name = "evm-scanner")]
#[command(about = "EVM bytecode vulnerability scanner using Jaccard similarity")]
struct Cli {
    /// Hex-encoded bytecode to scan (or pass via stdin)
    #[arg(short, long)]
    bytecode: Option<String>,

    /// Fetch bytecode from an EVM RPC endpoint
    #[arg(short, long)]
    rpc: Option<String>,

    /// Contract address to fetch (requires --rpc)
    #[arg(short, long)]
    address: Option<String>,

    /// N-gram window size for Jaccard comparison
    #[arg(short = 'w', long, default_value = "3")]
    ngram_window: usize,

    /// Output format: json or text
    #[arg(short, long, default_value = "json")]
    format: String,

    /// Chain name for display (ethereum, bsc, arbitrum)
    #[arg(short, long, default_value = "ethereum")]
    chain: String,
}

#[derive(Serialize)]
struct ScanReport {
    chain: String,
    address: Option<String>,
    bytecode_length: usize,
    instruction_count: usize,
    signature_matches: Vec<ScanMatch>,
    reentrancy_findings: Vec<ReentrancyFinding>,
    flash_loan_findings: Vec<FlashLoanFinding>,
    risk_level: String,
    summary: String,
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<String>,
}

fn fetch_bytecode_from_rpc(rpc_url: &str, address: &str) -> Result<Vec<u8>, String> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [address, "latest"],
        "id": 1
    });

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(rpc_url)
        .json(&payload)
        .send()
        .map_err(|e| format!("RPC request failed: {}", e))?;

    let rpc_resp: RpcResponse = resp.json().map_err(|e| format!("Failed to parse RPC response: {}", e))?;

    match rpc_resp.result {
        Some(hex_code) => {
            let clean = hex_code.strip_prefix("0x").unwrap_or(&hex_code);
            if clean == "0x" || clean.is_empty() {
                return Err("Address has no deployed code (EOA or empty)".to_string());
            }
            hex::decode(clean).map_err(|e| format!("Invalid hex in bytecode: {}", e))
        }
        None => Err("RPC returned null result".to_string()),
    }
}

fn determine_risk_level(matches: &[ScanMatch], reentrancy: &[ReentrancyFinding], flash_loan: &[FlashLoanFinding]) -> String {
    let matched_count = matches.iter().filter(|m| m.matched).count();
    let high_severity_reentrancy = reentrancy.iter().any(|f| f.severity == "HIGH");

    if high_severity_reentrancy || matched_count >= 3 {
        "CRITICAL".to_string()
    } else if matched_count >= 2 || !reentrancy.is_empty() {
        "HIGH".to_string()
    } else if matched_count == 1 || !flash_loan.is_empty() {
        "MEDIUM".to_string()
    } else {
        "LOW".to_string()
    }
}

fn generate_summary(matches: &[ScanMatch], reentrancy: &[ReentrancyFinding], flash_loan: &[FlashLoanFinding]) -> String {
    let matched: Vec<&ScanMatch> = matches.iter().filter(|m| m.matched).collect();
    if matched.is_empty() && reentrancy.is_empty() && flash_loan.is_empty() {
        return "No known vulnerability patterns detected.".to_string();
    }

    let mut parts = Vec::new();
    for m in &matched {
        parts.push(format!(
            "{} pattern match (Jaccard={:.3})",
            m.signature_name, m.jaccard_score
        ));
    }
    if !reentrancy.is_empty() {
        parts.push(format!(
            "{} CALL-before-SSTORE reentrancy site(s)",
            reentrancy.len()
        ));
    }
    if !flash_loan.is_empty() {
        parts.push(format!(
            "{} flash loan borrow-repay pattern(s)",
            flash_loan.len()
        ));
    }
    parts.join("; ")
}

fn main() {
    let cli = Cli::parse();

    // Obtain bytecode from one of: --bytecode flag, --rpc+--address, or stdin
    let bytecode = if let Some(hex_str) = &cli.bytecode {
        let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        hex::decode(clean).expect("Invalid hex bytecode")
    } else if let (Some(rpc), Some(addr)) = (&cli.rpc, &cli.address) {
        match fetch_bytecode_from_rpc(rpc, addr) {
            Ok(bc) => bc,
            Err(e) => {
                eprintln!("Error fetching bytecode: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input).expect("Failed to read stdin");
        let clean = input.trim().strip_prefix("0x").unwrap_or(input.trim());
        hex::decode(clean).expect("Invalid hex bytecode on stdin")
    };

    let instructions = disassemble(&bytecode);
    let signature_matches = scan_bytecode(&bytecode, cli.ngram_window);
    let reentrancy_findings = detect_call_before_sstore(&bytecode);
    let flash_loan_findings = detect_flash_loan_pattern(&bytecode);
    let risk_level = determine_risk_level(&signature_matches, &reentrancy_findings, &flash_loan_findings);
    let summary = generate_summary(&signature_matches, &reentrancy_findings, &flash_loan_findings);

    let report = ScanReport {
        chain: cli.chain,
        address: cli.address,
        bytecode_length: bytecode.len(),
        instruction_count: instructions.len(),
        signature_matches,
        reentrancy_findings,
        flash_loan_findings,
        risk_level,
        summary,
    };

    match cli.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        "text" => {
            println!("=== EVM Bytecode Vulnerability Scan ===");
            println!("Chain: {}", report.chain);
            if let Some(addr) = &report.address {
                println!("Address: {}", addr);
            }
            println!("Bytecode: {} bytes, {} instructions", report.bytecode_length, report.instruction_count);
            println!("Risk Level: {}", report.risk_level);
            println!();
            println!("--- Signature Matches ---");
            for m in &report.signature_matches {
                let status = if m.matched { "⚠ MATCH" } else { "  ok" };
                println!(
                    "  {} {} (Jaccard={:.4}, threshold={:.4})",
                    status, m.signature_name, m.jaccard_score, m.threshold
                );
                if m.matched {
                    println!("    → {}", m.description);
                }
            }
            println!();
            println!("--- Reentrancy Analysis ---");
            if report.reentrancy_findings.is_empty() {
                println!("  No CALL-before-SSTORE patterns found.");
            } else {
                for f in &report.reentrancy_findings {
                    println!(
                        "  [{}] {} at offset 0x{:04X} → SSTORE at 0x{:04X}",
                        f.severity, f.call_type, f.call_offset, f.sstore_offset
                    );
                }
            }
            println!();
            println!("--- Flash Loan Analysis ---");
            if report.flash_loan_findings.is_empty() {
                println!("  No flash loan patterns found.");
            } else {
                for f in &report.flash_loan_findings {
                    println!(
                        "  Pattern: {} | BALANCE checks: {} | External CALLs: {}",
                        f.pattern, f.balance_checks, f.external_calls
                    );
                }
            }
            println!();
            println!("Summary: {}", report.summary);
        }
        _ => {
            eprintln!("Unknown format: {}", cli.format);
            std::process::exit(1);
        }
    }
}
