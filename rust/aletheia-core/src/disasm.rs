//! x86/x64 disassembler. Port of `aletheia/disasm.py`.
//!
//! Backed by the pure-Rust `iced-x86` decoder (no C toolchain required).
//! Ships linear-sweep disassembly + a small recursive-descent walker that
//! follows direct call/jmp targets to build a basic function-level view.
//!
//! Correctness contract: for the SAME code bytes at the SAME base, the
//! address / size / mnemonic / operand-string of every produced instruction
//! matches capstone's output on the Python side. Formatter is Intel syntax
//! (Python default).

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction as IcedInsn, IntelFormatter,
    OpKind,
};
use serde::{Deserialize, Serialize};

/// A single decoded instruction. Mirrors `Instruction` on the Python side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub size: u32,
    pub mnemonic: String,
    pub op_str: String,
    #[serde(with = "hex_bytes")]
    pub bytes: Vec<u8>,
    /// Absolute destination for a DIRECT branch (call / jmp / jcc with an
    /// immediate operand). `None` for indirect and non-branches.
    pub target: Option<u64>,
    pub is_call: bool,
    pub is_ret: bool,
    /// Unconditional jump: no fallthrough.
    pub is_jmp: bool,
    /// Conditional branch (jcc): has both a taken target and a fallthrough.
    pub is_cond_jmp: bool,
}

impl Instruction {
    /// Address one past the last byte of this instruction.
    pub fn end(&self) -> u64 {
        self.address + self.size as u64
    }
    /// Convenience: any branch (call or jump, conditional or not).
    pub fn is_branch(&self) -> bool {
        self.is_call || self.is_jmp || self.is_cond_jmp
    }
}

// serde helper: hex-encode bytes for compact JSON transit.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = b.iter().map(|x| format!("{:02x}", x)).collect();
        s.serialize_str(&hex)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// Disassemble a byte slice as if mapped at `base`. Linear sweep — decodes
/// straight through and advances one byte on an undecodable input (the
/// classic linear-sweep recovery), so a data gap does not truncate everything
/// after it.
pub fn disassemble_linear(code: &[u8], base: u64, bits: u32) -> Vec<Instruction> {
    let mut out = Vec::new();
    let mut decoder = Decoder::with_ip(bits, code, base, DecoderOptions::NONE);
    let mut fmt = IntelFormatter::new();
    let mut insn = IcedInsn::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            // recovery: advance one byte + resync decoder
            let cur = decoder.ip();
            let next_off = (cur - base + 1) as usize;
            if next_off >= code.len() {
                break;
            }
            decoder = Decoder::with_ip(
                bits,
                &code[next_off..],
                base + next_off as u64,
                DecoderOptions::NONE,
            );
            continue;
        }
        out.push(convert(&insn, code, base, &mut fmt));
    }
    out
}

/// Recursive-descent disassembly from one or more entry points. Follows
/// direct calls + jumps; stops at rets / indirect terminators. Deduplicates
/// on address. Ordered by address in the returned vec.
pub fn disassemble_recursive(
    code: &[u8],
    base: u64,
    entries: &[u64],
    bits: u32,
) -> Vec<Instruction> {
    use std::collections::{BTreeMap, VecDeque};

    let mut work: VecDeque<u64> = entries.iter().copied().collect();
    let mut seen: BTreeMap<u64, Instruction> = BTreeMap::new();
    let mut fmt = IntelFormatter::new();

    while let Some(addr) = work.pop_front() {
        if seen.contains_key(&addr) {
            continue;
        }
        if addr < base {
            continue;
        }
        let start = (addr - base) as usize;
        if start >= code.len() {
            continue;
        }
        let slice = &code[start..];
        let mut decoder = Decoder::with_ip(bits, slice, addr, DecoderOptions::NONE);
        let mut insn = IcedInsn::default();
        loop {
            if !decoder.can_decode() {
                break;
            }
            decoder.decode_out(&mut insn);
            if insn.is_invalid() {
                break;
            }
            let converted = convert(&insn, code, base, &mut fmt);
            let ip = converted.address;
            if seen.contains_key(&ip) {
                break;
            }
            let is_ret = converted.is_ret;
            let is_uncond = converted.is_jmp;
            if let Some(target) = converted.target {
                work.push_back(target);
            }
            seen.insert(ip, converted);
            if is_ret || is_uncond {
                break;
            }
            // conditional branches fall through; the loop's decoder continues.
        }
    }

    seen.into_values().collect()
}

/// A basic block: a maximal straight-line run of instructions ending in a
/// branch, return, or the address just before another block starts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start: u64,
    pub end: u64,               // exclusive
    pub instructions: Vec<u64>, // addresses of insns in this block, in order
    pub succs: Vec<u64>,        // successor block starts
}

/// Build a CFG (list of basic blocks) from a set of decoded instructions.
/// Blocks start at branch targets + fall-throughs from conditional branches
/// + the first instruction.
pub fn build_cfg(insns: &[Instruction]) -> Vec<BasicBlock> {
    use std::collections::{BTreeMap, BTreeSet};
    if insns.is_empty() {
        return Vec::new();
    }
    let by_addr: BTreeMap<u64, &Instruction> = insns.iter().map(|i| (i.address, i)).collect();
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    leaders.insert(insns[0].address);
    for i in insns {
        if let Some(t) = i.target
            && by_addr.contains_key(&t)
        {
            leaders.insert(t);
        }
        if i.is_jmp || i.is_cond_jmp || i.is_call {
            let ft = i.end();
            if by_addr.contains_key(&ft) {
                leaders.insert(ft);
            }
        }
        if i.is_ret {
            let ft = i.end();
            if by_addr.contains_key(&ft) {
                leaders.insert(ft);
            }
        }
    }
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let leaders_v: Vec<u64> = leaders.iter().copied().collect();
    for (idx, &leader) in leaders_v.iter().enumerate() {
        let next_leader = leaders_v.get(idx + 1).copied().unwrap_or(u64::MAX);
        let mut instructions = Vec::new();
        let mut cur = leader;
        let mut end = leader;
        let mut succs = Vec::new();
        while cur < next_leader {
            let Some(&i) = by_addr.get(&cur) else {
                break;
            };
            instructions.push(cur);
            end = i.end();
            if i.is_ret {
                break;
            }
            if i.is_jmp {
                if let Some(t) = i.target {
                    succs.push(t);
                }
                break;
            }
            if i.is_cond_jmp {
                if let Some(t) = i.target {
                    succs.push(t);
                }
                succs.push(i.end()); // fallthrough
                break;
            }
            cur = i.end();
        }
        // A block that fell through into the next leader has that leader as
        // its sole successor (unless a branch already populated succs).
        if succs.is_empty() && by_addr.contains_key(&next_leader) && end == next_leader {
            succs.push(next_leader);
        }
        blocks.push(BasicBlock {
            start: leader,
            end,
            instructions,
            succs,
        });
    }
    blocks
}

/// Cross-references: for each address, the set of addresses that CALL or
/// unconditionally JMP to it. Direct branches only.
pub fn compute_xrefs(insns: &[Instruction]) -> std::collections::BTreeMap<u64, Vec<u64>> {
    let mut out: std::collections::BTreeMap<u64, Vec<u64>> = std::collections::BTreeMap::new();
    for i in insns {
        if let Some(t) = i.target
            && (i.is_call || i.is_jmp)
        {
            out.entry(t).or_default().push(i.address);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn convert(insn: &IcedInsn, code: &[u8], base: u64, fmt: &mut IntelFormatter) -> Instruction {
    // iced-x86 IntelFormatter's format_operands is private; format() produces
    // "mnemonic op1, op2, ..." which we split at the first whitespace.
    let mut full = String::new();
    fmt.format(insn, &mut full);
    let (mnemonic, op_str) = match full.split_once(char::is_whitespace) {
        Some((m, o)) => (m.to_string(), o.trim_start().to_string()),
        None => (full.clone(), String::new()),
    };
    let start = (insn.ip() - base) as usize;
    let end = (start + insn.len()).min(code.len());
    let bytes = code.get(start..end).unwrap_or(&[]).to_vec();

    let fc = insn.flow_control();
    let is_call = matches!(fc, FlowControl::Call | FlowControl::IndirectCall);
    let is_ret = matches!(fc, FlowControl::Return);
    let is_uncond_jmp = matches!(
        fc,
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
    );
    let is_cond_jmp = matches!(fc, FlowControl::ConditionalBranch);

    // Direct-branch target: first operand is an immediate branch target.
    let target = if (is_call || is_uncond_jmp || is_cond_jmp) && insn.op_count() > 0 {
        match insn.op0_kind() {
            OpKind::NearBranch64 => Some(insn.near_branch64()),
            OpKind::NearBranch32 => Some(insn.near_branch32() as u64),
            OpKind::NearBranch16 => Some(insn.near_branch16() as u64),
            OpKind::FarBranch32 => Some(insn.far_branch32() as u64),
            OpKind::FarBranch16 => Some(insn.far_branch16() as u64),
            _ => None,
        }
    } else {
        None
    };

    Instruction {
        address: insn.ip(),
        size: insn.len() as u32,
        mnemonic,
        op_str,
        bytes,
        target,
        is_call,
        is_ret,
        is_jmp: is_uncond_jmp,
        is_cond_jmp,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_disasm_mov_ret() {
        // 48 89 c3      mov rbx, rax
        // c3            ret
        let code = &[0x48, 0x89, 0xC3, 0xC3];
        let insns = disassemble_linear(code, 0x1000, 64);
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].mnemonic, "mov");
        assert_eq!(insns[0].address, 0x1000);
        assert_eq!(insns[0].size, 3);
        assert_eq!(insns[1].mnemonic, "ret");
        assert!(insns[1].is_ret);
    }

    #[test]
    fn direct_call_has_target() {
        // e8 05 00 00 00      call +5   (target: 0x100A)
        let code = &[
            0xE8, 0x05, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3,
        ];
        let insns = disassemble_linear(code, 0x1000, 64);
        assert!(insns[0].is_call);
        assert_eq!(insns[0].target, Some(0x100A));
    }

    #[test]
    fn direct_jcc_marked_conditional_with_target() {
        // 74 05          je +5   (target: 0x1007)
        let code = &[0x74, 0x05, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3];
        let insns = disassemble_linear(code, 0x1000, 64);
        assert!(insns[0].is_cond_jmp);
        assert_eq!(insns[0].target, Some(0x1007));
    }

    #[test]
    fn unconditional_jmp_marked() {
        // eb 02          jmp +2  (target: 0x1004)
        let code = &[0xEB, 0x02, 0x90, 0x90, 0xC3];
        let insns = disassemble_linear(code, 0x1000, 64);
        assert!(insns[0].is_jmp);
        assert!(!insns[0].is_cond_jmp);
        assert_eq!(insns[0].target, Some(0x1004));
    }

    #[test]
    fn recursive_follows_call() {
        // e8 05 00 00 00 (call to 0x100A)
        // c3             (ret at 0x1005)
        // (data 0x1006 .. 0x1009)
        // 48 31 c0 c3    (xor rax,rax; ret at 0x100A)
        let mut code = vec![
            0xE8, 0x05, 0x00, 0x00, 0x00, 0xC3, 0, 0, 0, 0, 0x48, 0x31, 0xC0, 0xC3,
        ];
        let insns = disassemble_recursive(&code, 0x1000, &[0x1000], 64);
        let addrs: Vec<u64> = insns.iter().map(|i| i.address).collect();
        assert!(addrs.contains(&0x1000), "should decode call");
        assert!(addrs.contains(&0x100A), "should follow call target");
        // We should NOT decode the data gap at 0x1006..0x100A.
        assert!(!addrs.contains(&0x1006));
        let _ = &mut code; // keep mut warning quiet
    }

    #[test]
    fn cfg_two_blocks_from_jcc() {
        // 0x1000: je +2   -> block ends here, succs = 0x1004 (target), 0x1002 (fallthrough)
        // 0x1002: nop
        // 0x1003: c3 ret  (or just terminator)
        // 0x1004: nop
        // 0x1005: c3 ret
        let code = &[0x74, 0x02, 0x90, 0xC3, 0x90, 0xC3];
        let insns = disassemble_linear(code, 0x1000, 64);
        let cfg = build_cfg(&insns);
        assert!(
            cfg.len() >= 2,
            "expected at least 2 blocks, got {}",
            cfg.len()
        );
        let entry = &cfg[0];
        assert_eq!(entry.start, 0x1000);
        assert!(entry.succs.contains(&0x1004), "jcc target should be a succ");
        assert!(
            entry.succs.contains(&0x1002),
            "fallthrough should be a succ"
        );
    }

    #[test]
    fn xrefs_records_call_targets() {
        // 0x1000: call 0x100A
        // 0x1005: nop nop nop nop nop
        // 0x100A: ret
        let code = &[0xE8, 0x05, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3];
        let insns = disassemble_linear(code, 0x1000, 64);
        let x = compute_xrefs(&insns);
        assert_eq!(x.get(&0x100A), Some(&vec![0x1000]));
    }
}
