# AGENTS.md

Guidance for AI agents and contributors working in this repository. Facts here are verified against
the tree; if you change the build, CI or release setup, update this file in the same PR.

## What this is

`iam-rs` is a provider-agnostic IAM policy engine: it parses, validates and evaluates IAM policy
documents, aiming for AWS IAM compatibility. Evaluation correctness is the product, so a change that
alters a decision is a breaking change even when it is a bug fix.

- Edition 2024. Default features: none. Optional feature: `utoipa`.
- Everything public is re-exported from [src/lib.rs](src/lib.rs) via `pub use core::*` /
  `pub use evaluation::*` / `pub use policy::*` / `pub use validation::*`. Any `pub` item in those
  modules is public API, so use `pub(crate)` / `pub(super)` freely for internals.

## Layout

| Path | Contents |
| --- | --- |
| [src/core/](src/core/) | Vocabulary types: `Arn`, `IAMAction`, `IAMEffect`, `IAMOperator`, `Principal`, `IAMResource`, `IAMVersion` |
| [src/policy/](src/policy/) | Document model: `IAMPolicy`, `IAMStatement`, `Condition` / `ConditionBlock` / `ConditionValue` |
| [src/evaluation/](src/evaluation/) | `PolicyEvaluator`, condition operators, `ArnMatcher`, policy variables, `Context` |
| [src/validation/](src/validation/) | Structural validation |
| [tests/](tests/) | Corpus and integration tests |
| [examples/](examples/) | `arn_demo`, `evaluation_demo`, `validation_demo` |

## Commands

Aliases come from [.cargo/config.toml](.cargo/config.toml).

```bash
cargo t                    # cargo test --workspace --all-features
cargo l                    # clippy --workspace --all-features --tests --examples --bins
cargo test --all-features  # the authoritative run: includes the utoipa schema tests
cargo test                 # default features — must also pass; not sufficient alone
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --all-features --no-deps
cargo run --example evaluation_demo
```

Run both feature sets. CI does (`stable`, `beta`, `nightly`), and the `utoipa`-only tests are the
ones that pin the published schemas to what the serializers actually write — issues 25 and 27 both
shipped a schema that disagreed with the wire format while CI looked green because
`--all-features` was not being run.

Lint levels are set in `Cargo.toml`: `correctness` and `suspicious` are **deny**; `style`,
`complexity`, `perf`, `pedantic`, `cargo` are warn. `clippy::missing_errors_doc` is allowed
crate-wide, though fallible public functions still carry `# Errors` sections — keep doing that.

CI runs `cargo clippy --all-targets --all-features -- -D warnings` on all three toolchains, and adds
the clippy component explicitly because only stable ships it. It does **not** run `cargo fmt --check`:
the tree is not rustfmt-clean (pre-existing drift in `arn.rs`, `operator.rs`, `policy.rs` and two test
blocks in `engine.rs`), so gates on formatting would fail immediately. Format your own hunks and
leave the rest alone.

## Change hygiene

- **One change per pull request.** If an issue bundles two independent fixes, split it into two PRs
  that both reference the issue (`Refs #N`) rather than one that closes it. A PR that mixes a
  behaviour change, a refactor and a version bump cannot be reviewed or reverted.
- Commit messages are a single imperative sentence with a capital letter and no `.` —
  `Reject policy variables that resolve to a wildcard`. PR titles may carry a `type:` prefix
  (`fix:`, `perf:`, `test:`, `docs:`).
- Do not add dependencies for convenience. The dependency list is deliberately short; a new
  dev-dependency needs justification in the PR body.
- No `unsafe`, no global mutable state, no unwrap on user-supplied input.

## Testing

Unit tests live in `#[cfg(test)] mod tests` at the bottom of the file they test; integration and
property tests live in [tests/](tests/).

Corpus data:

| File | Meaning |
| --- | --- |
| `tests/policies/N.json` | 64 AWS documentation example policies, keys sorted by `tests/proc-policies.sh` |
| `tests/requests/N.json` | Sample request documents |
| `tests/expected-decisions.json` | Pinned decision per policy/case, consumed by `test_policy_corpus_decisions` |
| `tests/arns.json` | ARN parse/match corpus |
| `tests/spec.json` | OpenAPI snapshot, see below |

Two rules that matter more than coverage numbers:

1. **Never derive an expected value from current engine output.** Expectations must come from IAM
   semantics and the AWS documentation the fixture is drawn from. Copying what the engine does
   freezes bugs into the test suite and makes the test a change detector rather than a specification.
   If a correctly-derived expectation fails, investigate: it may be an engine bug. Do not adjust the
   expectation to fit the engine unless you can explain why the engine is right.
2. **Prefer an independent reference implementation for algorithmic properties.** The wildcard and
   policy-variable property tests in [tests/proptest_matching.rs](tests/proptest_matching.rs) compare
   against a separately written reference; a test that reuses the code under test proves nothing.
   Recorded counterexamples live in `tests/proptest_matching.proptest-regressions` — do not delete
   them.

Scan tests over `tests/policies/` assert on filenames, so new fixture files must follow the existing
`N.json` convention.

## OpenAPI snapshot

`#[cfg(all(feature = "utoipa", test))]` tests in [src/lib.rs](src/lib.rs) compare the generated
document against `tests/spec.json`. `info.version` is compared separately against `CARGO_PKG_VERSION`
and stripped from both sides, so a version bump alone does not touch the snapshot — but adding,
removing or re-documenting a schema field does.

To regenerate, run and save the printed output:

```bash
cargo test --features utoipa test_generate_openapi_spec -- --nocapture
```

## Releases

Publishing is bound to a tag push and nothing else. Workflow: [.github/workflows/release.yml](.github/workflows/release.yml).

1. Bump `version` in [Cargo.toml](Cargo.toml). An evaluation-behaviour change is a breaking change:
   bump the minor version of `0.x` and say what changed in the PR body and the README.
2. Land the bump as its own PR.
3. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.

`release.yml` then:

- fails if the tag does not name the `Cargo.toml` version (both `vX.Y.Z` and `X.Y.Z` trigger),
- runs `cargo test --all-features` and `cargo publish --dry-run` **before** requesting a
  credential,
- exchanges a GitHub OIDC token for a thirty-minute crates.io credential. There is no
  `CARGO_REGISTRY_TOKEN` in this repository and there must never be one. Renaming the workflow file
  unbinds the crate, because crates.io checks the workflow filename.

crates.io has no undo. A published version cannot be edited.

## Environment notes

- Do not share one `CARGO_TARGET_DIR` between several git worktrees. Cargo will happily reuse
  artifacts from a different source tree, and the resulting test binary can pass or fail against code
  that is not the code you just edited. Give each worktree its own target directory.
- This project uses a worktree-per-branch workflow. Create them with `git worktree add -b <branch>
  ../iam-rs-wt/<name> origin/main` and keep the main checkout untouched.
- Newer `gh` releases fail `gh pr edit` / `gh issue view` with a Projects (classic) deprecation
  error. Use the REST API instead, e.g.
  `gh api repos/Foorack/iam-rs/issues/N --jq '.body'` or
  `gh api -X PATCH repos/Foorack/iam-rs/pulls/N -f body="$(cat body.md)"`.
