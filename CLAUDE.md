# coins

## AI-written tests

Every test Claude writes goes in the crate's `ai-tests/` directory, never
inline in `src/`. Each file there is a submodule of the source file it
tests, declared at the bottom of that source file. For
`src/common/status.rs`:

```rust
#[cfg(test)]
#[path = "../../ai-tests/common/status.rs"]
mod ai_tests;
```

- `ai-tests/` sits beside `src/` in each crate, e.g.
  `crates/ledger/ai-tests/`. Its layout mirrors `src/`: tests for
  `src/transports/native/hid.rs` live in
  `ai-tests/transports/native/hid.rs`.
- The module is always named `ai_tests`. As a submodule it reaches
  private items with `use super::*;`.
- `#[path]` resolves relative to the directory of the declaring file, so
  a file at `src/transports/native/hid.rs` declares
  `#[path = "../../../ai-tests/transports/native/hid.rs"]`.
- Human-written tests stay where they are: inline `mod test` blocks and
  the crate's `tests/` directory. Do not add Claude-written tests to
  either.
