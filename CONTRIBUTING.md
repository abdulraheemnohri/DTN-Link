# Contributing

1. Fork, create a feature branch.
2. `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test --workspace` must pass.
3. Conventional commits (`feat:`, `fix:`, `docs:`, `test:`).
4. No secrets, no fake transport implementations — hardware-dependent features
   must be marked as such.
