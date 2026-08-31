"""Aletheia -- defensive reverse-engineering toolkit for Windows PEs.

The antithesis of Lethe: where Lethe conceals, Aletheia reveals. Static triage
(pe/detect/extract/signatures/disasm), a dynamic layer built on a scriptable
Windows debugger (debugger/procdump/unpack/imports/behavior/antidebug/pdb), and
a static core that lifts x64 to a bounded-op IR, does SSA data-flow and
simplification, recovers control-flow structure, and emits C-like pseudocode
(ir/dataflow/simplify/symexec/structuring/decompile), plus a project model with
JSON persistence and a binary-diff mode (project/diff).

See the top-level README for a tour. This file re-exports the most-used public
API so ``from aletheia import decompile_function`` works without knowing the
internal module layout.
"""
from __future__ import annotations

__version__ = "0.1.0"

# --- static triage ---------------------------------------------------------
from aletheia.pe import parse as parse_pe, PEInfo, Section, shannon_entropy
from aletheia.detect import analyze as detect_packer, Verdict
from aletheia.extract import (
    extract_strings, extract_resources, extract_all,
    interesting_strings, entropy_map, section_entropy, high_entropy_spans,
    FoundString, ResourceEntry, ExtractResult,
)
from aletheia.signatures import (
    scan, scan_pe, identify_functions, identify_in_pe,
    classify_by_structure, classify_functions_by_structure,
    structural_signatures,
    Pattern, Rule, Match, FuncSignature, StructuralSignature,
)

# --- dynamic layer ---------------------------------------------------------
from aletheia.debugger import Debugger
from aletheia.dump import dump_pe, dump_module
from aletheia.procdump import (
    list_modules, dump_process, dump_module as dump_module_pid,
    open_process, read_memory, make_reader, ModuleInfo,
)
from aletheia.unpack import (
    UnpackMonitor, run_unpack, UnpackResult,
    is_dynamic_executable, size_of_image, ImageMap,
)
from aletheia.imports import (
    parse_exports, resolve_imports, classify_api, purpose_summary,
    Exports, ResolvedImport, Purpose,
)
from aletheia.behavior import (
    BehaviorMonitor, run_trace, BehaviorEvent, WatchEntry,
)
from aletheia.antidebug import DebugCloak, cloak_peb, run_cloaked, query_peb_base
from aletheia.pdb import (
    resolve_module_symbols, read_rsds, fetch_pdb, parse_pdb,
    PdbInfo, PdbSymbol, RSDSInfo, SymbolCache,
)

# --- static core: disasm -> IR -> data-flow -> structure -> decompile ------
from aletheia.disasm import (
    disassemble_linear, disassemble_recursive, build_cfg, compute_xrefs,
    disasm_pe, Instruction, BasicBlock, DisasmResult,
)
from aletheia.ir import (
    IRFunction, IRBlock, IRInsn, Value, VTag, Op,
    lift_instruction, lift_block, lift_function,
)
from aletheia.dataflow import (
    build_ssa, constant_fold, dead_code_eliminate, memory_ssa,
    dominators, dominance_frontiers,
    is_phi, ssa_base_name, ssa_version,
    PHI_OP_CODE, MEM_SSA_OP_CODE,
)
from aletheia.simplify import (
    simplify, opaque_predicate_pass, flattening_pass, mba_pass,
    SimplifyResult,
)
from aletheia.symexec import (
    initial_state, symexec_path, is_reachable, path_condition,
    analyze_reachability, enumerate_paths,
    SymState, Term, Kind, Reachability,
)
from aletheia.structuring import (
    structure, StructuredFunction, SNode, NodeKind,
    natural_loops, is_loop_header, immediate_post_dominators, post_order,
)
from aletheia.decompile import (
    decompile_function, decompile_function_stream,
    emit, emit_stream, recover_types, recover_signature,
    DecompiledFunction, TypeGuess, FunctionSignature, Argument,
)

# --- project + diff --------------------------------------------------------
from aletheia.project import Project, Function, Comment, Label, ArtifactSummary
from aletheia.diff import (
    diff_projects, pair_functions, render,
    ProjectDiff, FunctionDiff, PairScore,
)

import types as _types

# Public API: everything we explicitly re-exported above, excluding submodules
# that `from aletheia.x import ...` binds as attributes and the `annotations`
# future flag.
__all__ = sorted(
    name for name, val in globals().items()
    if not name.startswith("_")
    and name != "annotations"
    and not isinstance(val, _types.ModuleType)
)
del _types
