## Summary

<!-- What does this change and why? Link the issue it fixes, if any (Fixes #123). -->

## How it was tested

<!--
Say what you ran and on which kernel(s), for example:
- cargo test --workspace
- cargo xtask test-e2e on 6.12.48 (all scenarios) / --only c,l
- cargo xtask bench, before and after (paste the table for changes to the BPF programs,
  the drain loop or the engine)
- verifier instruction counts from `sudo fsblame doctor --json | jq .ops`, for BPF changes
-->

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes, and new behaviour or fixed bugs have tests
- [ ] `cargo xtask test-e2e` passes, if the change affects what fsblame reports
- [ ] README.md, CHANGELOG.md and doc comments are updated for user-visible changes
- [ ] AGENTS.md is updated for changes to the BPF programs, the wire ABI, the architecture or
      the end-to-end scenarios
