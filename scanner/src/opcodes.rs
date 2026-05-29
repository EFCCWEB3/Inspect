/// EVM opcode definitions relevant to vulnerability detection.
///
/// Reference: https://www.evm.codes/

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    Stop,
    Add,
    Mul,
    Sub,
    Div,
    Mod,
    Exp,
    Lt,
    Gt,
    Eq,
    IsZero,
    And,
    Or,
    Not,
    Sha3,
    Address,
    Balance,
    Origin,
    Caller,
    CallValue,
    CallDataLoad,
    CallDataSize,
    CallDataCopy,
    CodeSize,
    CodeCopy,
    ExtCodeSize,
    ExtCodeCopy,
    ReturnDataSize,
    ReturnDataCopy,
    SLoad,
    SStore,
    Jump,
    JumpI,
    Pc,
    MLoad,
    MStore,
    Gas,
    JumpDest,
    Push1,
    Push2,
    Push4,
    Push20,
    Push32,
    Dup1,
    Dup2,
    Swap1,
    Swap2,
    Log0,
    Log1,
    Log2,
    Log3,
    Log4,
    Call,
    CallCode,
    Return,
    DelegateCall,
    Create2,
    StaticCall,
    Revert,
    SelfDestruct,
    Unknown(u8),
}

impl Opcode {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x00 => Opcode::Stop,
            0x01 => Opcode::Add,
            0x02 => Opcode::Mul,
            0x03 => Opcode::Sub,
            0x04 => Opcode::Div,
            0x06 => Opcode::Mod,
            0x0A => Opcode::Exp,
            0x10 => Opcode::Lt,
            0x11 => Opcode::Gt,
            0x14 => Opcode::Eq,
            0x15 => Opcode::IsZero,
            0x16 => Opcode::And,
            0x17 => Opcode::Or,
            0x19 => Opcode::Not,
            0x20 => Opcode::Sha3,
            0x30 => Opcode::Address,
            0x31 => Opcode::Balance,
            0x32 => Opcode::Origin,
            0x33 => Opcode::Caller,
            0x34 => Opcode::CallValue,
            0x35 => Opcode::CallDataLoad,
            0x36 => Opcode::CallDataSize,
            0x37 => Opcode::CallDataCopy,
            0x38 => Opcode::CodeSize,
            0x39 => Opcode::CodeCopy,
            0x3B => Opcode::ExtCodeSize,
            0x3C => Opcode::ExtCodeCopy,
            0x3D => Opcode::ReturnDataSize,
            0x3E => Opcode::ReturnDataCopy,
            0x51 => Opcode::MLoad,
            0x52 => Opcode::MStore,
            0x54 => Opcode::SLoad,
            0x55 => Opcode::SStore,
            0x56 => Opcode::Jump,
            0x57 => Opcode::JumpI,
            0x58 => Opcode::Pc,
            0x5A => Opcode::Gas,
            0x5B => Opcode::JumpDest,
            0x60 => Opcode::Push1,
            0x61 => Opcode::Push2,
            0x63 => Opcode::Push4,
            0x73 => Opcode::Push20,
            0x7F => Opcode::Push32,
            0x80 => Opcode::Dup1,
            0x81 => Opcode::Dup2,
            0x90 => Opcode::Swap1,
            0x91 => Opcode::Swap2,
            0xA0 => Opcode::Log0,
            0xA1 => Opcode::Log1,
            0xA2 => Opcode::Log2,
            0xA3 => Opcode::Log3,
            0xA4 => Opcode::Log4,
            0xF1 => Opcode::Call,
            0xF2 => Opcode::CallCode,
            0xF3 => Opcode::Return,
            0xF4 => Opcode::DelegateCall,
            0xF5 => Opcode::Create2,
            0xFA => Opcode::StaticCall,
            0xFD => Opcode::Revert,
            0xFF => Opcode::SelfDestruct,
            other => Opcode::Unknown(other),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Opcode::Stop => "STOP",
            Opcode::Add => "ADD",
            Opcode::Mul => "MUL",
            Opcode::Sub => "SUB",
            Opcode::Div => "DIV",
            Opcode::Mod => "MOD",
            Opcode::Exp => "EXP",
            Opcode::Lt => "LT",
            Opcode::Gt => "GT",
            Opcode::Eq => "EQ",
            Opcode::IsZero => "ISZERO",
            Opcode::And => "AND",
            Opcode::Or => "OR",
            Opcode::Not => "NOT",
            Opcode::Sha3 => "SHA3",
            Opcode::Address => "ADDRESS",
            Opcode::Balance => "BALANCE",
            Opcode::Origin => "ORIGIN",
            Opcode::Caller => "CALLER",
            Opcode::CallValue => "CALLVALUE",
            Opcode::CallDataLoad => "CALLDATALOAD",
            Opcode::CallDataSize => "CALLDATASIZE",
            Opcode::CallDataCopy => "CALLDATACOPY",
            Opcode::CodeSize => "CODESIZE",
            Opcode::CodeCopy => "CODECOPY",
            Opcode::ExtCodeSize => "EXTCODESIZE",
            Opcode::ExtCodeCopy => "EXTCODECOPY",
            Opcode::ReturnDataSize => "RETURNDATASIZE",
            Opcode::ReturnDataCopy => "RETURNDATACOPY",
            Opcode::MLoad => "MLOAD",
            Opcode::MStore => "MSTORE",
            Opcode::SLoad => "SLOAD",
            Opcode::SStore => "SSTORE",
            Opcode::Jump => "JUMP",
            Opcode::JumpI => "JUMPI",
            Opcode::Pc => "PC",
            Opcode::Gas => "GAS",
            Opcode::JumpDest => "JUMPDEST",
            Opcode::Push1 => "PUSH1",
            Opcode::Push2 => "PUSH2",
            Opcode::Push4 => "PUSH4",
            Opcode::Push20 => "PUSH20",
            Opcode::Push32 => "PUSH32",
            Opcode::Dup1 => "DUP1",
            Opcode::Dup2 => "DUP2",
            Opcode::Swap1 => "SWAP1",
            Opcode::Swap2 => "SWAP2",
            Opcode::Log0 => "LOG0",
            Opcode::Log1 => "LOG1",
            Opcode::Log2 => "LOG2",
            Opcode::Log3 => "LOG3",
            Opcode::Log4 => "LOG4",
            Opcode::Call => "CALL",
            Opcode::CallCode => "CALLCODE",
            Opcode::Return => "RETURN",
            Opcode::DelegateCall => "DELEGATECALL",
            Opcode::Create2 => "CREATE2",
            Opcode::StaticCall => "STATICCALL",
            Opcode::Revert => "REVERT",
            Opcode::SelfDestruct => "SELFDESTRUCT",
            Opcode::Unknown(_) => "UNKNOWN",
        }
    }

    /// Number of bytes this opcode's immediate data occupies.
    /// PUSH1..PUSH32 consume 1..32 bytes respectively.
    pub fn push_size(byte: u8) -> usize {
        if (0x60..=0x7F).contains(&byte) {
            (byte - 0x5F) as usize
        } else {
            0
        }
    }
}

/// A single disassembled instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    pub offset: usize,
    pub opcode: Opcode,
    pub raw: u8,
    pub immediate: Vec<u8>,
}

/// Disassemble raw EVM bytecode into a sequence of instructions.
pub fn disassemble(bytecode: &[u8]) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut i = 0;
    while i < bytecode.len() {
        let raw = bytecode[i];
        let opcode = Opcode::from_byte(raw);
        let push_bytes = Opcode::push_size(raw);
        let immediate = if push_bytes > 0 && i + 1 + push_bytes <= bytecode.len() {
            bytecode[i + 1..i + 1 + push_bytes].to_vec()
        } else if push_bytes > 0 {
            bytecode[i + 1..].to_vec()
        } else {
            Vec::new()
        };
        instructions.push(Instruction {
            offset: i,
            opcode,
            raw,
            immediate,
        });
        i += 1 + push_bytes;
    }
    instructions
}
