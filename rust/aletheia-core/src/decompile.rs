//! Lightweight x64 → C-flavored pseudocode emitter.
//!
//! Trade-off honest up front: this is **not** a port of the full Python
//! pipeline (`ir.py` + `dataflow.py` + `simplify.py` + `structuring.py` +
//! `decompile.py`, ~4,500 LoC of SSA-driven analysis). It's a lightweight
//! lowering that reads a function's disassembly and emits per-instruction
//! C-flavored statements, with a *single* structuring pattern collapsed:
//! the "if-then triangle" (JCC-to-forward-address followed by a clean
//! linear run that falls through to the JCC target). Everything else
//! stays in `goto` + label form, which is legal C and honest about the
//! shape the analyzer actually recovered.
//!
//! For full SSA + memory-SSA + opaque-predicate simplification + Cifuentes-
//! style structuring + labeled loops + type/signature inference, run the
//! Python side:
//!
//! ```text
//! python aletheia.py decompile <path> --rva <RVA>
//! ```
//!
//! ## What this emits
//!
//! - `void func_<rva>(void) { ... }`
//! - `<reg> = <expr>;` for `mov` / `lea` / arithmetic / bitwise
//! - `_flags = cmp(a, b);` / `_flags = test(a, b);` for flag-setters
//! - `if (<cond>) { <block> }` for the if-then triangle pattern
//! - `if (<cond>) goto L_<addr>;` and `L_<addr>:` for anything else
//! - `call(fn_<addr>);` for direct calls, `call(<op>);` for indirect
//! - `return;` for `ret`
//! - `_asm("<mnemonic> <ops>");` fallback so nothing is silently dropped
//!
//! Register names stay as-is (`rax`, `rbx`, ...); no SSA renaming.
//! Correctness contract: every instruction contributes exactly one line;
//! no drops, no fabrication.

use crate::disasm::{BasicBlock, Instruction};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Result of a decompile pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompiledFunction {
    pub name: String,
    /// The rendered C-flavored source.
    pub source: String,
    /// Honest notes about what was and wasn't recovered.
    pub warnings: Vec<String>,
}

/// Decompile a function's linearly-disassembled instructions.
///
/// `insns` must be in address order (as returned by `disasm::disassemble_*`).
/// `blocks` is the CFG for the same instructions (from `disasm::build_cfg`).
pub fn decompile(name: &str, insns: &[Instruction], blocks: &[BasicBlock]) -> DecompiledFunction {
    let mut warnings: Vec<String> = Vec::new();
    if insns.is_empty() {
        return DecompiledFunction {
            name: name.to_string(),
            source: format!("void {}(void) {{\n    /* empty function */\n}}\n", name),
            warnings: vec!["no instructions to decompile".into()],
        };
    }

    // Build the "labeled address" set: every block start after the first,
    // plus every direct-branch target we observe in the instruction stream.
    let mut labels: HashSet<u64> = HashSet::new();
    for b in blocks.iter().skip(1) {
        labels.insert(b.start);
    }
    for i in insns {
        if let Some(t) = i.target {
            if i.is_cond_jmp || i.is_jmp {
                labels.insert(t);
            }
        }
    }

    // Build address → index map for the if-then-triangle scan.
    let addr_to_idx: HashMap<u64, usize> =
        insns.iter().enumerate().map(|(i, insn)| (insn.address, i)).collect();

    let mut src = String::new();
    src.push_str(&format!("void {}(void) {{\n", name));

    // Walk the instruction stream. Every step either emits one line, or
    // collapses a whole `if (cond) { ... }` triangle and skips its body.
    let mut i: usize = 0;
    while i < insns.len() {
        let insn = &insns[i];

        // Emit a label at the head of this instruction if anyone jumps here.
        // We suppress the label if the instruction is at index 0 (function
        // entry — the function name is the label).
        if i > 0 && labels.contains(&insn.address) {
            src.push_str(&format!("L_{:x}:\n", insn.address));
        }

        // Try to fold an if-then triangle here.
        if let Some(triangle) = try_fold_if_then(insns, i, &addr_to_idx, &labels) {
            emit_if_then(&mut src, insns, &triangle);
            i = triangle.after_idx;
            continue;
        }

        // Otherwise emit this one instruction.
        src.push_str("    ");
        src.push_str(&lower_instr(insn));
        src.push('\n');
        i += 1;
    }

    src.push_str("}\n");

    // Honest warnings.
    let unknown = insns.iter().filter(|i| lower_is_fallback(i)).count();
    if unknown > 0 {
        warnings.push(format!(
            "{} instructions lowered to `_asm(\"...\")` fallback (unsupported class in the MVP emitter)",
            unknown
        ));
    }
    warnings.push(
        "Lightweight lowering only — no SSA, no memory-SSA, no opaque-predicate reduction. \
         For the full pipeline (structuring, type inference, MBA fold) run \
         `python aletheia.py decompile <path> --rva <RVA>`."
            .into(),
    );

    DecompiledFunction {
        name: name.to_string(),
        source: src,
        warnings,
    }
}

// ---------------------------------------------------------------------------
// If-then triangle detection
// ---------------------------------------------------------------------------

/// One recognized `if (cond) { ... }` fold.
struct IfThen {
    /// The JCC instruction's own index in `insns`.
    jcc_idx: usize,
    /// Range of `insns` that form the "then" body (exclusive of the JCC).
    body_start: usize,
    body_end: usize,
    /// Index at which to resume the outer walk (past the body).
    after_idx: usize,
}

fn try_fold_if_then(
    insns: &[Instruction],
    i: usize,
    addr_to_idx: &HashMap<u64, usize>,
    labels: &HashSet<u64>,
) -> Option<IfThen> {
    let jcc = &insns[i];
    if !jcc.is_cond_jmp {
        return None;
    }
    let target = jcc.target?;
    // Target must be inside this function (mapped in the address index) and
    // strictly after the fall-through — i.e. a *forward* branch.
    let target_idx = *addr_to_idx.get(&target)?;
    if target_idx <= i + 1 {
        return None;
    }
    // Body must be a clean linear run: no other label in the middle, and no
    // instruction in the body branches out of the body region (except the
    // last one, which may `jmp` past the target — that's still fine, it just
    // means the outer walk resumes at that jmp's destination).
    for k in (i + 1)..target_idx {
        let a = insns[k].address;
        // Any label inside the body means someone else branches here —
        // we can't fold safely without risking control-flow drop.
        if k > i + 1 && labels.contains(&a) {
            return None;
        }
        // Any conditional branch in the body invalidates the triangle
        // shape (would need nested structuring, out of scope).
        if insns[k].is_cond_jmp {
            return None;
        }
        // An unconditional jmp is OK only if it's the LAST instruction of the
        // body (i.e. right before the target); anything earlier is exotic.
        if insns[k].is_jmp && k != target_idx - 1 {
            return None;
        }
        // A ret in the middle of the body means we don't fall through to
        // the JCC target — still legal, still a valid if-then, we handle it.
    }
    Some(IfThen {
        jcc_idx: i,
        body_start: i + 1,
        body_end: target_idx,
        after_idx: target_idx,
    })
}

fn emit_if_then(src: &mut String, insns: &[Instruction], t: &IfThen) {
    // Invert the JCC condition: JCC-to-target means "if COND then skip body";
    // rewritten as "if NOT COND then execute body".
    let jcc = &insns[t.jcc_idx];
    let cond = negate_cond(&jcc.mnemonic);
    src.push_str(&format!("    if ({}) {{\n", cond));
    for k in t.body_start..t.body_end {
        // Nested labels inside the body were rejected by the fold guard, so
        // no label emission here.
        src.push_str("        ");
        src.push_str(&lower_instr(&insns[k]));
        src.push('\n');
    }
    src.push_str("    }\n");
}

// ---------------------------------------------------------------------------
// Per-instruction lowering
// ---------------------------------------------------------------------------

/// Return true if `lower_instr` would fall back to the `_asm(...)` form on
/// this instruction — used only for the summary warning count.
fn lower_is_fallback(insn: &Instruction) -> bool {
    if insn.is_ret || insn.is_call || insn.is_jmp || insn.is_cond_jmp { return false; }
    let mn = insn.mnemonic.as_str();
    let parts_len = insn.op_str.split(',').filter(|s| !s.trim().is_empty()).count();
    match (mn, parts_len) {
        ("mov" | "movsx" | "movzx" | "movsxd" | "lea", 2) => false,
        ("add" | "sub" | "and" | "or" | "xor" | "shl" | "shr" | "sar"
        | "imul" | "sal", 2) => false,
        ("inc" | "dec" | "neg" | "not", 1) => false,
        ("cmp" | "test", 2) => false,
        ("push" | "pop", 1) => false,
        ("nop", _) => false,
        ("xchg", 2) => false,
        _ => true,
    }
}

fn lower_instr(insn: &Instruction) -> String {
    let mn = insn.mnemonic.as_str();
    let ops = insn.op_str.as_str();

    if insn.is_ret {
        return "return;".to_string();
    }
    if insn.is_call {
        return match insn.target {
            Some(t) => format!("call(fn_{:x});", t),
            None => format!("call({});", ops),
        };
    }
    if insn.is_cond_jmp {
        let cond = jcc_cond(mn);
        return match insn.target {
            Some(t) => format!("if ({}) goto L_{:x};", cond, t),
            None => format!("if ({}) goto ??;", cond),
        };
    }
    if insn.is_jmp {
        return match insn.target {
            Some(t) => format!("goto L_{:x};", t),
            None => format!("goto {};", ops),
        };
    }

    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
    match (mn, parts.len()) {
        ("mov" | "movsx" | "movzx" | "movsxd", 2) =>
            format!("{} = {};", parts[0], parts[1]),
        ("lea", 2) =>
            format!("{} = &{};", parts[0], strip_ptr_prefix(parts[1])),
        ("add", 2) => bin_assign(parts[0], "+", parts[1]),
        ("sub", 2) => bin_assign(parts[0], "-", parts[1]),
        ("and", 2) => bin_assign(parts[0], "&", parts[1]),
        ("or",  2) => bin_assign(parts[0], "|", parts[1]),
        ("xor", 2) if parts[0] == parts[1] => format!("{} = 0;", parts[0]),
        ("xor", 2) => bin_assign(parts[0], "^", parts[1]),
        ("shl" | "sal", 2) => bin_assign(parts[0], "<<", parts[1]),
        ("shr", 2) => bin_assign(parts[0], ">>", parts[1]),
        ("sar", 2) => format!("{} = (int64_t){} >> {};", parts[0], parts[0], parts[1]),
        ("imul", 2) => bin_assign(parts[0], "*", parts[1]),
        ("inc", 1) => format!("{} = {} + 1;", parts[0], parts[0]),
        ("dec", 1) => format!("{} = {} - 1;", parts[0], parts[0]),
        ("neg", 1) => format!("{} = -{};", parts[0], parts[0]),
        ("not", 1) => format!("{} = ~{};", parts[0], parts[0]),
        ("cmp", 2) => format!("_flags = cmp({}, {});", parts[0], parts[1]),
        ("test", 2) => format!("_flags = test({}, {});", parts[0], parts[1]),
        ("push", 1) => format!("push({});", parts[0]),
        ("pop",  1) => format!("{} = pop();", parts[0]),
        ("nop", _) => "/* nop */".to_string(),
        ("xchg", 2) => format!("swap(&{}, &{});", parts[0], parts[1]),
        _ => format!("_asm(\"{} {}\");", mn, ops),
    }
}

/// `dst = dst OP src;` — the most common binary arithmetic pattern on x64.
fn bin_assign(dst: &str, op: &str, src: &str) -> String {
    format!("{} = {} {} {};", dst, dst, op, src)
}

/// Strip an x86 memory operand's `qword ptr` / `dword ptr` size prefix,
/// leaving just the `[base + index*scale + disp]` form. Cosmetic only.
fn strip_ptr_prefix(op: &str) -> &str {
    for pfx in &["qword ptr ", "dword ptr ", "word ptr ", "byte ptr ",
                 "xmmword ptr ", "ymmword ptr ", "zmmword ptr ", "tbyte ptr "] {
        if let Some(rest) = op.strip_prefix(pfx) {
            return rest;
        }
    }
    op
}

/// Translate a JCC mnemonic to a C-like condition on `_flags`.
fn jcc_cond(mn: &str) -> &'static str {
    match mn {
        "je"  | "jz"                     => "_flags.eq",
        "jne" | "jnz"                    => "!_flags.eq",
        "jl"  | "jnge"                   => "_flags.slt",
        "jle" | "jng"                    => "_flags.sle",
        "jg"  | "jnle"                   => "_flags.sgt",
        "jge" | "jnl"                    => "_flags.sge",
        "jb"  | "jc"   | "jnae"          => "_flags.ult",
        "jbe" | "jna"                    => "_flags.ule",
        "ja"  | "jnbe"                   => "_flags.ugt",
        "jae" | "jnb"  | "jnc"           => "_flags.uge",
        "js"                             => "_flags.sign",
        "jns"                            => "!_flags.sign",
        "jo"                             => "_flags.of",
        "jno"                            => "!_flags.of",
        "jp"  | "jpe"                    => "_flags.parity",
        "jnp" | "jpo"                    => "!_flags.parity",
        "jcxz" | "jecxz" | "jrcxz"       => "_flags.cx_zero",
        _ => "_flags.?",
    }
}

/// Negation used when we fold `if (JCC-to-target) skip body` into
/// `if (!JCC-condition) execute body`.
fn negate_cond(mn: &str) -> String {
    // Map each mnemonic to its logical inverse.
    let inv = match mn {
        "je"  | "jz"  => "jne",
        "jne" | "jnz" => "je",
        "jl"  | "jnge" => "jge",
        "jle" | "jng"  => "jg",
        "jg"  | "jnle" => "jle",
        "jge" | "jnl"  => "jl",
        "jb"  | "jc"   | "jnae" => "jae",
        "jbe" | "jna"           => "ja",
        "ja"  | "jnbe"          => "jbe",
        "jae" | "jnb"  | "jnc"  => "jb",
        "js"  => "jns",
        "jns" => "js",
        "jo"  => "jno",
        "jno" => "jo",
        "jp"  | "jpe" => "jnp",
        "jnp" | "jpo" => "jp",
        _ => return format!("!({})", jcc_cond(mn)),
    };
    jcc_cond(inv).to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::{disassemble_linear, build_cfg};

    #[test]
    fn ret_only() {
        // Just `ret` — should decompile to a single-line function.
        let insns = disassemble_linear(&[0xC3], 0x1000, 64);
        let blocks = build_cfg(&insns);
        let out = decompile("f", &insns, &blocks);
        assert!(out.source.contains("return;"), "got:\n{}", out.source);
    }

    #[test]
    fn simple_arith() {
        // mov eax, ebx ; add eax, 1 ; ret
        let bytes = [0x89, 0xD8, 0x83, 0xC0, 0x01, 0xC3];
        let insns = disassemble_linear(&bytes, 0x1000, 64);
        let blocks = build_cfg(&insns);
        let out = decompile("demo", &insns, &blocks);
        assert!(out.source.contains("eax = ebx;"), "got:\n{}", out.source);
        assert!(out.source.contains("eax = eax + 1;"), "got:\n{}", out.source);
        assert!(out.source.contains("return;"), "got:\n{}", out.source);
    }

    #[test]
    fn if_then_triangle_folded() {
        // mov eax, ebx      ; 2 bytes
        // cmp eax, 0xA      ; 3 bytes
        // jne L             ; 2 bytes  (jne over the add)
        // add eax, 1        ; 3 bytes
        // L: ret            ; 1 byte
        // Total: 11 bytes. jne is at 0x1005, jumps to 0x100A. Body at 0x1007..0x100A.
        let bytes = [0x89, 0xD8, 0x83, 0xF8, 0x0A, 0x75, 0x03, 0x83, 0xC0, 0x01, 0xC3];
        let insns = disassemble_linear(&bytes, 0x1000, 64);
        let blocks = build_cfg(&insns);
        let out = decompile("demo", &insns, &blocks);
        // jne-around-body should become `if (_flags.eq)` (invert of !eq).
        assert!(out.source.contains("if (_flags.eq)"), "got:\n{}", out.source);
        // Body inside the if.
        assert!(out.source.contains("eax = eax + 1;"), "got:\n{}", out.source);
        // No stray goto for the folded triangle.
        assert!(!out.source.contains("goto L_"), "got:\n{}", out.source);
    }

    #[test]
    fn call_lowered_to_call_fn() {
        // call rel32 → call(fn_XXXX);
        // Use a simple direct call: E8 xx xx xx xx (5 bytes), targeting +5 (which is past the ret).
        // At 0x1000: E8 00 00 00 00 = call 0x1005; then ret.
        let bytes = [0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3];
        let insns = disassemble_linear(&bytes, 0x1000, 64);
        let blocks = build_cfg(&insns);
        let out = decompile("demo", &insns, &blocks);
        assert!(out.source.contains("call(fn_1005);"), "got:\n{}", out.source);
    }

    #[test]
    fn unknown_op_falls_back() {
        // int3 - unlikely to be lowered, should fall back to _asm.
        let insns = disassemble_linear(&[0xCC], 0x1000, 64);
        let blocks = build_cfg(&insns);
        let out = decompile("demo", &insns, &blocks);
        assert!(out.source.contains("_asm(\"int3"), "got:\n{}", out.source);
    }
}
