## Summary

Describe the problem and the smallest change that solves it.

## Validation

- [ ] `python -m pytest -q`
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo test --workspace --all-targets --locked`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `npm ci && npm run lint && npm run build`
- [ ] No hostile sample was executed outside a disposable VM

## Security impact

Note any change to file handling, process execution, IPC, or the experimental driver.
