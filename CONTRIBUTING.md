# Contributing to zac-bn254

Thanks for the interest. The short version: open an issue first for
anything bigger than a typo, send a PR that keeps the test suite
green, and sign your commits with the DCO.

## Before you start

For anything that is not a one-line fix — new features, format
changes, refactors that move public types, dependency bumps that
touch arkworks — open an issue first. Two reasons:

1. The wire format in `docs/SPEC.md` is normative. Anything that
   changes a byte on the wire is a major version bump and needs
   discussion before code.
2. The Groth16 prover ports snarkjs's exact FFT pipeline including
   the `R⁻²` Montgomery correction. Changes there need cross-verify
   to stay green in both directions. It is easier to flag that early
   than to undo a PR that broke it.

## Local development

```
cargo build --workspace
cargo test -p zac-bn254
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
bash scripts/e2e_demo.sh
cd node-tools && npm install && npm run cross-verify
```

CI runs the same six lanes (lint, test, MSRV, `cargo audit`,
`cargo deny check`, end-to-end cross-verify). If your change does not
pass them locally, it will not pass them in CI either.

For changes that touch the prover or verifier, run the forgery vector
example as well:

```
cargo run --example forgery_vectors -p zac-bn254
```

All eight attack constructions should be rejected with the listed
error codes.

## Commit style

- Short imperative subject (under 70 characters). `fix overflow in
  proof_decode`, not `Fixed a bug`.
- Body wrapped at 72 columns explains the why. The diff already
  shows the what.
- Sign every commit with `git commit -s`. This appends a
  `Signed-off-by:` trailer that certifies the contribution under the
  Developer Certificate of Origin (text below).
- No co-author trailers from AI tools or pair-programming bots in
  this repo's history. Author is the person making the change.

## Pull requests

- One PR per logical change. A relicense, a bug fix, and a perf
  improvement are three PRs.
- Update `docs/CHANGELOG.md` in the same PR. The entry goes under a
  new version header if your change is release-worthy, otherwise
  under an unreleased section.
- If your PR touches `docs/SPEC.md`, note in the PR body which clauses
  changed and whether the change is normative or editorial.
- The branch will get rebased on top of `main` before merge. Keep
  your history clean — squash trivial fixups before opening the PR.

## Developer Certificate of Origin

By signing off on a commit (`git commit -s`, which appends
`Signed-off-by: Your Name <your.email>`), you certify the following:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

The DCO is the same model the Linux kernel and most large open
source projects use. It is lighter than a CLA — there is no separate
document to sign and no bot infrastructure to maintain — and it is
sufficient as a legal record of contribution provenance.

## License of your contribution

Any contribution you submit is licensed under the same dual MIT OR
Apache-2.0 terms as the rest of the project. The Apache-2.0 grant
includes a patent license from you for the contribution, which is
why the dual license is the standard choice in cryptography crates.
If you cannot agree to that, do not submit the contribution.
