# AGENTS.md

## Project Overview

CLI utility for generating blocklist.rpz files for firewalls. Rust project with
Rust 1.88+.

## Key Files

- `blocklist-generator.toml` - Main configuration with blocklist URLs
  and filters
- `blocked-names.txt` - Additional blocked names to override/append
- `src/main.rs` - Entry point; orchestrates fetching, filtering, and writing

## Development Commands

```bash
# Run the application
./blocklist-generator

# Format code
cargo fmt
dprint check

# Lint
cargo clippy -- -D warnings

# Run tests
cargo test

# Run single test
cargo test <test_name>

# Check with MSRV
cargo +1.88.0 check

# Coverage (uses justfile)
just coverage

# Review insta snapshots
just insta-snapshot-review

# Generate CLI markdown docs
just markdown-docs
```

## Pre-commit Hooks

Automatically runs on commit:

- commitizen (for commit messages);
- rustfmt, cargo-check, clippy;
- gitleaks (security scanning);
- yamlfmt;
- trailing-whitespace, end-of-file-fixer, check-yaml, check-json; and
- no-commit-to-branch.

## Testing

- Uses `insta` for snapshot-based tests.
- Uses `assert_fs` for file system testing.
- Uses `wiremock` for HTTP mocking in tests.
- Snapshot files in `src/snapshots/`.

## Code Style

- Clippy pedantic & all lints enabled
  (`#![warn(clippy::all, clippy::pedantic)]`).
- Uses `dprint` for JSON, markdown, and TOML formatting.
- Rustfmt for Rust code formatting.

## Important Constraints

- Rust version: 1.88+ (required for askama 0.16.0).
- CI checks: stable, beta toolchains, and MSRV (1.88.0).
- Coverage requires `grcov` and LLVM tools.
- Generated files (`blocklist.rpz`, `domain-blocklist.txt`,
  `zone-block-general.conf`) are in .gitignore.
