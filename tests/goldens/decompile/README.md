# Decompiler goldens

Each `.golden.c` file is the **exact expected `.source`** produced by
`aletheia.decompile.decompile_function` for one hand-built IR fixture in
`tests/test_decompile_golden.py`. The runner reads the file and compares
byte-for-byte; a mismatch fails the test with a unified diff.

**These files are tracked**. Changes to the decompiler that alter the emitted
output MUST land as an intentional golden update, reviewed alongside the code
change that caused the drift. That is the whole point of the lock:
pre-Rust-rewrite, no accidental churn.

## Regenerating (accepting new output)

Set the sentinel env var and re-run the golden test file. Every fixture whose
output changed is rewritten in place; each rewritten fixture is `skip`ped for
that run so pytest tells you which files it touched.

```bash
# bash / zsh
ALETHEIA_UPDATE_GOLDENS=1 python -m pytest tests/test_decompile_golden.py -v
```

```powershell
# PowerShell
$env:ALETHEIA_UPDATE_GOLDENS = "1"
python -m pytest tests/test_decompile_golden.py -v
Remove-Item Env:ALETHEIA_UPDATE_GOLDENS
```

Then re-run WITHOUT the env var to confirm the new goldens lock:

```bash
python -m pytest tests/test_decompile_golden.py -q
```

Review every changed `.golden.c` in the diff before committing. If a change
looks wrong (a genuine regression, not an intended improvement) DO NOT commit
the updated golden -- fix the decompiler first.

## First-run bootstrap

If a `.golden.c` file is missing entirely, the runner treats that as a
regeneration event (same code path as the env var) and writes it out. This
lets a brand-new fixture ship on its first `pytest` run without ceremony. Once
the file exists it is locked -- delete-and-regenerate is an intentional act.

## Fixture roster

The 12 fixtures pin one decompiler feature each. See
`tests/test_decompile_golden.py` for the hand-built IR each one emits.

| Fixture                    | Feature under lock                                     |
| :------------------------- | :----------------------------------------------------- |
| `assign_immediate`         | `ASSIGN dst = IMM`                                     |
| `arith_add`                | Binary `ADD` infix                                     |
| `sub_and_return`           | `SUB` + signature inference off an arg reg             |
| `nested_arith`             | Flat multi-op arithmetic (SUB, IMUL, ADD)              |
| `if_only`                  | `IF` structuring with no `else` arm                    |
| `if_else`                  | `IF`/`ELSE` structuring across a diamond               |
| `while_loop`               | Pre-test `WHILE` structuring                           |
| `two_arg_returning_sum`    | Two-arg signature inference (`rcx`, `rdx`)             |
| `void_no_args`             | `void sub(void)` from the `xor eax, eax` idiom         |
| `struct_two_fields`        | Synthetic-struct recovery (two distinct field disps)   |
| `stack_roundtrip`          | `memory_ssa` load rewrite (`LOAD` -> `ASSIGN`)         |
| `opaque_predicate_true`    | `opaque_predicate_pass` eliding an always-false branch |

## Why the emitted output looks the way it does

The goldens capture what the current pipeline **actually emits**, not what a
prettier decompiler would emit. Some knowingly-imperfect shapes are locked
here on purpose so a future improvement is a *deliberate* golden update:

* Empty `if { } else { }` arms when `constant_fold` collapses two register
  assignments into a single trailing `phi`.
* Fallthrough `phi(x, x)` lines at post-dominator joins.
* `t = rax * rax` staying as a temp assignment plus a `/* cmp t, 0; sets flags */`
  comment after simplify (the CMP's operands survive DCE via the SETFLAG root,
  and a stray CMP is emitted as a comment rather than fabricating an `if`).

If you *intend* to fix any of these, that is a decompiler change plus a golden
regeneration in the same commit.
