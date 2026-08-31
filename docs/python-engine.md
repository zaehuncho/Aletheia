# Python engine

The `aletheia` package is the reference implementation for Aletheia's PE analysis pipeline. It requires Python 3.12 or newer. Capstone is optional; without it, disassembly-dependent stages return explicit reduced-capability results.

| Module | Responsibility |
|---|---|
| `pe`, `imports`, `pdb` | PE parsing, imports, and public-symbol lookup |
| `detect`, `signatures`, `extract` | Packer signals, signature matching, and payload extraction |
| `disasm`, `ir`, `dataflow` | Disassembly, SSA-like IR, and data-flow analysis |
| `simplify`, `structuring`, `decompile` | Simplification, control-flow structuring, and C-like output |
| `symexec`, `behavior` | Bounded symbolic exploration and behavior summaries |
| `debugger`, `antidebug`, `unpack` | Windows debugger orchestration and dynamic unpack observation |
| `dump`, `procdump` | Module and process-memory dump support |
| `project`, `diff` | Analysis persistence and result comparison |

Install the library alone with `python -m pip install -e .`. For the complete local test suite, including the optional Capstone backend, use `python -m pip install -e ".[dev]"`.

Run `python -m pytest -q` from the repository root. Golden decompiler output lives under `tests/goldens/decompile`; only regenerate it for an intentional, reviewed behavior change.
