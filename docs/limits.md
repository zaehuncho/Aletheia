# Analysis limits

Aletheia is an analyst aid, not a verdict engine or containment boundary.

- Packer and protector matches are heuristics. Treat confidence as prioritization, then verify against the cited signals and the binary.
- The Rust decompiler performs lightweight instruction lowering and limited triangle folding. The Python pipeline is more capable, but neither output is source recovery.
- Symbolic exploration is bounded and is not a complete SMT proof of reachability.
- Public PDB lookup does not recover private symbols, full type information, or source lines.
- Dynamic analysis executes the selected binary with the current user's authority. It is a debugger, not a sandbox; use a disposable, snapshotted Windows VM with networking isolated as appropriate.
- The `hv` tree is experimental source. It has not been signed, loaded, or runtime-validated and is excluded from normal release artifacts.

When adding a heuristic, document the evidence it uses, likely false positives and false negatives, and the test corpus that exercises it.
