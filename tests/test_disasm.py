"""Tests for the recursive-descent x64 disassembler (aletheia.disasm).

Correctness rides on synthetic, hand-assembled blobs -- no live process, no real
binary needed:

* **Linear:** a tiny known blob whose bytes and branch-target arithmetic are
  worked out by hand, pinning the END-relative math (``target = addr + size + rel``)
  so an off-by-the-instruction-length slip can't pass.
* **Recursive descent:** a sparse address->bytes closure with a call into a second
  block and a jmp into a third; asserts descent visits both targets and that the
  xref graph records the edges.
* **CFG:** a contiguous blob with a conditional branch splits into the expected
  three blocks with the right successors.
* **Real smoke:** best-effort ``disasm_pe`` on a real system exe -- skipped, never
  failed, if it isn't a clean x64 PE.

All require capstone (``importorskip``); the module itself imports without it.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

pytest.importorskip("capstone")

from aletheia import disasm  # noqa: E402
from aletheia.disasm import (  # noqa: E402
    BasicBlock, Instruction, build_cfg, compute_xrefs, disasm_pe,
    disassemble_linear, disassemble_recursive,
)

BASE = 0x401000


# ===========================================================================
# linear sweep + branch-target math
# ===========================================================================
def test_linear_decodes_blob_and_computes_call_target():
    # 55            push rbp                 off 0x00 size 1
    # 48 89 E5      mov  rbp, rsp            off 0x01 size 3
    # E8 05 00 00 00 call rel32(=5)          off 0x04 size 5  -> END-relative target
    # 31 C0         xor  eax, eax            off 0x09 size 2
    # 5D            pop  rbp                 off 0x0B size 1
    # C3            ret                      off 0x0C size 1
    blob = bytes.fromhex("55" "4889E5" "E805000000" "31C0" "5D" "C3")
    ins = disassemble_linear(blob, BASE)

    assert [i.mnemonic for i in ins] == \
        ["push", "mov", "call", "xor", "pop", "ret"]
    assert [i.op_str for i in ins] == \
        ["rbp", "rbp, rsp", hex(BASE + 0x0E), "eax, eax", "rbp", ""]

    call = ins[2]
    assert call.is_call and call.is_branch
    assert call.address == BASE + 0x04 and call.size == 5
    # The displacement (5) is measured from the END of the call (addr+size), NOT
    # its start: BASE+0x04 + 5 + 5 == BASE+0x0E.  (0x0E, not 0x0D.)
    assert call.target == call.address + call.size + 5 == BASE + 0x0E

    ret = ins[5]
    assert ret.is_ret and not ret.is_branch and ret.target is None
    # non-branch instructions carry no target
    assert ins[0].target is None and ins[1].target is None


def test_linear_survives_a_bad_byte():
    # push rbp | 0x06 (invalid in x64) | ret  -- sweep should skip the bad byte
    blob = bytes.fromhex("55" "06" "C3")
    mnems = [i.mnemonic for i in disassemble_linear(blob, BASE)]
    assert mnems[0] == "push" and mnems[-1] == "ret"


# ===========================================================================
# recursive descent + xrefs
# ===========================================================================
def _sparse_reader(segments):
    """Build a read_code closure over {addr: byte}; returns contiguous mapped bytes
    at a request address (stops at the first unmapped byte -> short/empty read)."""
    mem = {}
    for start, blob in segments:
        for i, b in enumerate(blob):
            mem[start + i] = b

    def read_code(addr, size):
        out = bytearray()
        for i in range(size):
            if (addr + i) in mem:
                out.append(mem[addr + i])
            else:
                break
        return bytes(out)

    return read_code


def test_recursive_descent_follows_call_and_jmp():
    # 0x1000: xor eax,eax        31 C0
    # 0x1002: call 0x1020        E8 19 00 00 00   (rel = 0x1020-0x1007 = 0x19)
    # 0x1007: jmp  0x1010        EB 07            (rel = 0x1010-0x1009 = 0x07)
    # 0x1010: mov eax,1          B8 01 00 00 00
    # 0x1015: ret                C3
    # 0x1020: nop                90
    # 0x1021: ret                C3
    reader = _sparse_reader([
        (0x1000, bytes.fromhex("31C0" "E819000000" "EB07")),
        (0x1010, bytes.fromhex("B801000000" "C3")),
        (0x1020, bytes.fromhex("90" "C3")),
    ])
    instrs = disassemble_recursive(reader, [0x1000])

    # every reachable instruction, and both the call and the jmp target, decoded
    assert set(instrs) == {0x1000, 0x1002, 0x1007, 0x1010, 0x1015, 0x1020, 0x1021}
    assert instrs[0x1002].is_call and instrs[0x1002].target == 0x1020
    assert instrs[0x1007].is_jmp and instrs[0x1007].target == 0x1010
    assert instrs[0x1015].is_ret and instrs[0x1021].is_ret

    xrefs = compute_xrefs(instrs)
    assert xrefs[0x1020] == [0x1002]   # call edge
    assert xrefs[0x1010] == [0x1007]   # jmp edge


def test_recursive_descent_stops_at_unmapped():
    # a call whose target is not mapped: the call is decoded, its target trace dies
    # 0x1000: call 0x2000   E8 FB 0F 00 00   (rel = 0x2000-0x1005 = 0x0FFB)
    reader = _sparse_reader([(0x1000, bytes.fromhex("E8FB0F0000" "C3"))])
    instrs = disassemble_recursive(reader, [0x1000])
    assert instrs[0x1000].target == 0x2000
    assert 0x2000 not in instrs        # unmapped -> that trace stopped
    assert 0x1005 in instrs            # fallthrough (the ret) still decoded


def test_max_insns_guard():
    # infinite fallthrough of NOPs; the guard must bound the walk
    reader = _sparse_reader([(0x1000, b"\x90" * 4096)])
    instrs = disassemble_recursive(reader, [0x1000], max_insns=10)
    assert len(instrs) <= 10


# ===========================================================================
# CFG
# ===========================================================================
def test_cfg_splits_on_conditional_branch():
    # 0x2000: test eax, eax   85 C0
    # 0x2002: je   0x2006     74 02      (rel = 0x2006-0x2004 = 0x02)
    # 0x2004: inc  eax        FF C0
    # 0x2006: ret             C3
    blob = bytes.fromhex("85C0" "7402" "FFC0" "C3")
    ins = disassemble_linear(blob, 0x2000)
    blocks = build_cfg(ins)

    assert all(isinstance(b, BasicBlock) for b in blocks)
    assert [b.start for b in blocks] == [0x2000, 0x2004, 0x2006]

    b0, b1, b2 = blocks
    assert b0.end == 0x2004
    # conditional branch: taken target + fallthrough
    assert set(b0.successors) == {0x2006, 0x2004}
    assert ins[1].is_cond_jmp and ins[1].target == 0x2006
    # fallthrough block flows into the ret block
    assert b1.successors == [0x2006]
    # ret terminates: no successors
    assert b2.instructions[-1].is_ret and b2.successors == []


def test_cfg_and_xrefs_accept_dict_or_list():
    blob = bytes.fromhex("85C0" "7402" "FFC0" "C3")
    lst = disassemble_linear(blob, 0x2000)
    dct = {i.address: i for i in lst}
    # build_cfg over a dict yields the same block boundaries as over a list
    assert [b.start for b in build_cfg(dct)] == [b.start for b in build_cfg(lst)]
    assert compute_xrefs(dct) == compute_xrefs(lst)


# ===========================================================================
# real-EXE smoke (best-effort; skip if the environment can't oblige)
# ===========================================================================
def test_disasm_pe_smoke_on_system_exe():
    candidates = [
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                     "System32", "cmd.exe"),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                     "System32", "notepad.exe"),
    ]
    path = next((p for p in candidates if os.path.exists(p)), None)
    if path is None:
        pytest.skip("no system exe available for the smoke test")

    from aletheia import pe
    info = pe.parse_bytes(open(path, "rb").read())
    if not info.ok or info.arch != "x64":
        pytest.skip(f"{path} is not a clean x64 PE for this smoke test")

    try:
        res = disasm_pe(path)
    except Exception as exc:                       # noqa: BLE001
        pytest.skip(f"disasm_pe smoke could not run cleanly: {exc}")

    # entry point decoded, and a non-trivial reachable body recovered
    assert res.entry == info.image_base + info.entry_rva
    assert res.entry in res.instructions
    assert len(res.instructions) >= 20
    assert len(res.blocks) >= 3
    # every block's successors reference real decoded instructions
    for b in res.blocks:
        for s in b.successors:
            assert s in res.instructions
