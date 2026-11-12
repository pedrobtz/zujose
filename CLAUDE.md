# CLAUDE.md

<!-- markdownlint-disable-next-line MD013 -->
This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

zujose signs, verifies, encrypts and decrypts JOSE objects: JWS, JWE, JWK
and JWK sets, and JWTs with claim validation, in both the compact and the
JSON serializations. Its callers are R code talking to OAuth 2.0 and OpenID
Connect providers, services that take signed assertions, and Shiny or
Plumber apps that issue or check tokens. It contains no cryptography and no
compiled code. Primitives come from `zucrypt`, Base64url from `zuutf` and
JSON from `zujson`. zujose owns the JOSE layer: serializations, header rules,
keys, algorithm policy and claim checks. It is not an OAuth client, not a
key store and not a fetcher, and it performs no I/O.

The specification is [`.agents/design.md`](.agents/design.md), adopted from
[RFC 0062](https://github.com/pedrobtz/packages/blob/main/rfcs/started/0062-zujose-jose-tokens.md).
It outranks this file. The package was scaffolded as `zujwt` and renamed
back to the RFC's name, `zujose`, on 2026-11-03, before any release:
condition classes are `zujose_*` and the information function is
`zujose_info()`. Public functions are named after the object they work
on: `jwt_*`, `jws_*`, `jwe_*` and `jwk_*` (renamed from one `jose_`
prefix on 2026-11-03, design §7.1). `jose_peek()` and `jose_limits()` keep
`jose_` because they apply to any JOSE object.

## Current state

Scaffolded 2026-11-02 with `create-pkg.sh`. Stages 0–9 are done
(2026-11-03): every algorithm of design §3. Codec; `oct`, RSA, EC and
X25519 keys (JWK and PEM) and key sets; JWS with `HS*`, `RS*`, `PS*` and
`ES*`; JWT; and JWE with `dir`, `A*KW`, `A*GCMKW`, `PBES2-*`, `RSA-OAEP`,
`RSA-OAEP-256`, decrypt-only `RSA1_5` and `ECDH-ES` (with the Concat KDF in
R) key management and `A*CBC-HS*` and `A*GCM` content encryption.
Asymmetric keys stay JWK members; `rsa_crypt_key()` and `ec_crypt_key()`
build the zucrypt key for each operation. Stage 10 added the README, the
pkgdown articles (Get started, migrating from `jose`, the JWKS resolver)
and the JWE oracle. Next is Stage 11, Full CI. The
roadmap in `.agents/roadmap.md` takes it to v0.1.0. The design's release
gate (§11.2) holds the CRAN submission until `zuutf` and `zucrypt` (>= 0.5.0)
are on CRAN. Randomness comes from `zucrypt`'s development version
(`Remotes: pedrobtz/zucrypt`), as do AES-GCM and PBKDF2 (zucrypt Stage
14a), RSA (15a) and the curves (16a).

## Stage tracking

Progress toward the next version is tracked as GitHub sub-issues, so the
parent issue shows a progress bar such as "6 of 7".

- **One parent issue per target version**, titled with the bare version, for
  example `v0.1.0`. `v0.1.0` issue: created by `pkg-roadmap`.
- **One sub-issue per roadmap stage**, titled as the roadmap titles it, for
  example `Stage 3 — R interface`, and linking to that section. The number of
  stages is whatever the roadmap has; there is no fixed scale.
- **Every tracking issue carries the `stage` label**, so it can be told apart
  from bug and feature issues and left out of open-issue counts.
- **Close a stage by merging its pull request.** Put `Closes #<n>` in the
  body of the stage's pull request. Never close a stage whose exit criteria
  are not met; record a deviation in the roadmap first.
- **The roadmap stays authoritative.** The issues record which stages are
  done, not what a stage requires. Adding, removing or renaming a stage
  means editing the roadmap and the sub-issues in the same change.
- **Each stage has a CI tier, `quick` or `full`.** The roadmap sets it, and
  `quick` is the default. See Continuous integration for what each means.
  The second-to-last stage, `Full CI`, runs the full set and fixes what it
  finds before `v0.1.0 readiness`.
- Close the parent issue when CRAN accepts the version and it is tagged.
  Opening a parent issue implies at least one stage sub-issue; a parent with
  no sub-issues shows no progress on the board.

## Versioning

A new package develops at `0.0.0.9000` and targets `0.1.0` for its first CRAN
release. Set `Version: 0.1.0` and the matching `NEWS.md` heading when the
package enters `Pre-flight`. Bump to `0.1.0.9000` only after CRAN accepts it,
never before: a `.9000` version above an unreleased `0.1.0` heading is wrong.

Until the first release the R API may change freely. Sibling packages can
still depend on this one before CRAN does, through `Remotes:` or `LinkingTo:`.
A package that others wait on should reach CRAN first.

## Commands

Run from the package root.

```sh
Rscript -e 'devtools::load_all()'                # compile src/ and load
Rscript -e 'devtools::document()'                # roxygen -> NAMESPACE, man/
Rscript -e 'devtools::test()'                    # full testthat suite
Rscript -e 'devtools::test(filter = "<name>")'   # one test file
Rscript -e 'devtools::test(shuffle = TRUE)'      # order independence
Rscript -e 'devtools::check()'                   # R CMD check
air format .                                     # format R sources
```

## Architecture

To be written as stages land; see `.agents/design.md` §6. Pure R, no `src/`.

## Invariants that are easy to break

These are fixed by the design (§6, §8, §12) before any code exists.

- **No compiled code.** Every primitive is an exported `zucrypt` function.
  JWA constructions over primitives (`A*CBC-HS*`, AES key wrap, Concat KDF)
  are R code tested against RFC vectors. Never touch `zucrypt`'s C archive.
- **`algorithms` has no default** in any verifying or decrypting function,
  and the key type must agree with `alg`. `none` is never implemented, not
  even behind a flag. A default here reopens algorithm confusion.
- **Policy runs before cryptography.** A header that fails the allow-list,
  `crit` or limits never reaches `zucrypt`.
- **Signing input and AAD use the received protected header bytes**, never
  a re-serialized header. Re-serializing breaks valid tokens from other
  implementations.
- **Keys come only from the caller.** `jwk`, `x5c`, `jku` and `x5u` in a
  header are never used as keys or fetched.
- **Every JWE decryption failure after policy raises one class with one
  message.** A distinct error per cause is a padding or unwrap oracle.
- **Base64url is strict and canonical.** No padding, no whitespace, no
  non-zero trailing bits, so every token has one encoding.
- **Messages never echo key material or decrypted bytes**, and printing a
  key never shows secret members.

## Testing conventions

- **Self-sufficient.** Every test builds its own inputs inside the
  `test_that()` block. No file-scope objects.
- **Self-contained.** Global state goes through `withr::local_*()`, randomised
  input through `withr::local_seed()`. Tests write only under `tempdir()`.
- **Assert on condition classes, never message text.** Use
  `expect_error(..., class = "<pkg>_<kind>_error")`. Wording belongs in
  snapshot tests.
- **Order independence.** `devtools::test(shuffle = TRUE)` is part of the
  definition of done.
- **Borrow a conformance suite before writing one.** Mainstream
  implementations in Python, Java, Go or Node usually ship a test corpus.
  Use it as an oracle rather than inventing cases by hand. Here the corpus
  is the RFC test vectors, RFC 7520 (the JOSE cookbook) first, committed
  under `tests/testthat/fixtures/` with a manifest (design §10). PyJWT is the
  oracle for JWS and JWT, through fixtures under `fixtures/oracle/` that
  `tools/make-oracle-fixtures.py` writes offline (`--check` re-verifies
  them). Fixtures that need another implementation are made the same way,
  with Python packages; `Suggests` holds only `testthat`. JWE has no
  oracle at check time; a development-only job checks it against a Python
  or JavaScript JOSE library. The RFC 7520 fixtures are regenerated with
  `tools/rfc7520-fixtures.R`; never edit them by hand.
- **Helpers live in `tests/testthat/helper-*.R`.** `helper-jose.R` reads
  the RFC 7520 fixtures (`rfc7520_manifest()`, `rfc7520_token()`), builds
  tokens (`b64_json()`, `compact_jws()`), holds the RFC 7519 and RFC 7797
  vectors, generates the malformed corpus (`malformed_corpus()`), and
  `local_no_decoding()` fails a test that decodes a part before its limit
  check. `helper-keys.R` reads the RFC 7520 keys (`rfc7520_key()`,
  `rfc7520_jwks()`) and holds the RFC 7638 vector. `rfc7515_key()` is the
  RFC 7515 A.1 HMAC key; `expect_same_json()` compares JSON
  serializations whatever their member order. `decode_at_1000()` signs a
  claims set and decodes it at a fixed time, for the claim-check tests.
  `oracle_pem()`, `oracle_key()` and `oracle_tokens()` read the PyJWT
  fixtures, and `oracle_now()` is a time before their `exp`.
  `oracle_zujose_tokens()` reads the tokens zujose signed for PyJWT to
  verify (`tools/make-zujose-tokens.R`), and `oracle_claims()` PyJWT's
  claim verdicts (`tools/make-claim-verdicts.py`). `wycheproof_table()`
  reads a Wycheproof fixture (`keys`, `signatures` or `jose`) and
  `wycheproof_key()` one of its keys, both written by
  `tools/make-wycheproof.py` from a pinned Wycheproof commit.
  `oracle_thumbprints()` reads the jwcrypto thumbprints that
  `tools/make-jwk-thumbprints.py` writes. `rfc7517_jwks()` reads the RFC
  7517 Appendix A sets, which `tools/rfc7516-7517-fixtures.R` extracts,
  and `expect_set_members()` holds a parsed set to one member by member.
  `rfc_value()` and `rfc_octets()` read the RFC 7517 Appendix C and RFC
  7516 A.1 values the same script extracts. `oracle_jwe_vectors()` reads
  the jwcrypto known answers that `tools/make-jwe-vectors.py` writes with
  fixed keys and ephemeral keys, and `oracle_jwe_json()` the jwcrypto
  JWE JSON serializations that `tools/make-jwe-json.py` writes.
  `rfc7520_text()` reads the §5 plaintexts and password, and
  `rfc7520_factor()` the generated factors (CEKs, IVs, salts, encrypted
  keys); `tools/rfc7520-fixtures.R` extracts both. `pbes2_token()` builds a
  PBES2 header for the `p2c`/`p2s` checks.
  `encrypt_fixed()` encrypts with a fixed CEK and IV, as the RFC vectors
  do; `hex()` reads hex text; `rfc7516_a3()`, `rfc7516_a4()`,
  `rfc7518_cbc()` and `rfc3394_vectors()` hold the JWE vectors. The RFC
  7518 Appendix B fixture is regenerated with
  `tools/rfc7518-cbc-vectors.R`.
  `expect_limit_straddle()` checks a limit at `limit - 1`, `limit` and
  `limit + 1`, optionally under `local_no_decoding()`;
  `protected_bytes()`, `local_pbes2_reached()` and `nested_json()` build
  its inputs, and `rsa_2040_jwk()` is a public key under the 2048-bit
  minimum.
- **Keep the suite inside the CRAN time budget.** The whole suite takes
  about 80 seconds.

## Assurance

@.claude/shared/assurance.md

`.agents/assurance.md` records how zujose meets that standard: its kinds,
the oracle behind each boundary and the straddle of each limit. A change
that adds a boundary or a limit adds its row, and CI (`assurance.yaml`)
checks the file. A gap is written `gap #<issue>`.

## Definition of done

`devtools::document()` and `devtools::check()` clean, meaning 0 errors, 0
warnings and 0 notes. The one allowed note is "New submission" before the first
release. `devtools::test(shuffle = TRUE)` green. CI green at the change's
tier: the quick profile for a `quick` roadmap stage or an ordinary pull
request, the full profile for a `full` stage, `Full CI`, and every release.
A user-facing change also needs a test, roxygen documentation and a `NEWS.md`
entry.

## Releasing to CRAN

- **CI is the pre-submission check.** The `pedrobtz/r-actions` R CMD check runs
  `--as-cran` on the CRAN-like runners and containers, and it replaces
  win-builder, the macOS builder and R-hub. None of them is a release step,
  and `cran-comments.md` lists the CI legs as its test environments.
- **Entering `Pre-flight`.** The roadmap's feature stages are done, the
  version is set as in Versioning, `NEWS.md` and `cran-comments.md` are
  written, and CI is green. Only submission work remains.
- **Before submitting,** run `pkg-critical-review` once the roadmap is
  implemented and fix what it files, then `pkg-cran-review`, and resolve
  every finding. Both skills are in `pedrobtz/r-skills`.
- **The pretest is automated and does not read `cran-comments.md`.** A NOTE
  that is explained but not fixed gets the upload archived. Fix the NOTE, as
  under Vendored native code, instead of justifying it.
- **After acceptance,** `pkg-post-cran` tags the submitted commit with the
  bare version, `0.1.0` (no `v`), publishes the GitHub release, bumps to
  `0.1.0.9000`, closes the version's parent issue and moves the board card.

## Editing rules

- roxygen comments are the source. Never edit `man/` or `NAMESPACE` by hand.
- Edit `README.Rmd`, not the generated `README.md`.
- Keep prose simple and short. One idea per sentence.
- Wrap roxygen text at 80 characters and run `air format .` on R sources.
- Use `lower_snake_case`, and prefix internal native symbols with `<pkg>_`.
- Keep hard runtime dependencies at zero unless a recorded design decision
  says otherwise.
- Export and document public functions. Do not create roxygen topics for
  internal ones.

## Continuous integration

Workflows come from `pedrobtz/r-actions`. Call those reusable workflows instead
of writing bespoke ones, and pin a released tag rather than `main`. Pin a
workflow that holds a write token, such as `coverage.yml`, to a commit, with
the tag in a comment. The `R-CMD-check` workflow must call `r-cmd-check.yml`,
because a hand-rolled one does not count as the pre-submission check. This package
calls `r-cmd-check.yml@v1` and `coverage.yml@v1`. `pkgdown.yaml` is the
usethis workflow, not an r-actions one. `jwe-oracle.yaml` is bespoke, as
r-actions has nothing like it: it runs `tools/jwe-oracle/`, where zujose
and Python's `jwcrypto` exchange JWE tokens for every `alg`/`enc` pair,
and flattened and general JSON serializations with `aad` and unprotected
headers, on
pull requests that touch `R/` or the oracle, and by hand. It is development-only
and never part of R CMD check.

The articles live in `vignettes/articles/`, which `.Rbuildignore` keeps
out of the tarball: they are pkgdown-only, need no `Suggests`, and are
built against the installed package.

Small edits get a small run. The shared workflows look at the files a pull
request changes, compared with its merge base:

- **Markdown only**, such as `README.md`, `NEWS.md` or `cran-comments.md`,
  skips every check. Only coverage and the pkgdown site run.
- **`DESCRIPTION` or `README.Rmd` as well**, and nothing else, adds one R CMD
  check on Ubuntu R-release.
- **Any other file** runs everything.

So put a README or `DESCRIPTION` touch-up in its own pull request. Once a pull
request changes code, every later push to it runs every workflow.

### Quick by default, full by exception

The full profile is slow. gctorture at step 20 alone has taken 36 to 107
minutes on sibling packages. Waiting on it between roadmap stages was the
main thing slowing roadmaps down, so:

- **Pull requests run the quick profile.** It should finish in under five
  minutes. If it doesn't, raise gctorture's `quick-step` or trim
  `quick-containers` in the caller workflows; never cut the full profile.
- **A `full` roadmap stage takes the `full-ci` label** and merges only on a
  green full run. The roadmap gives the reason in the stage's `**CI.**`
  line, for example first compiled code, a `PROTECT` or finalizer change, a
  vendored library, or a Windows-only path.
- **Don't wait on the full run a merge starts** on the default branch, and
  cancel older full runs it supersedes. A failure that only the full set
  shows goes on the `Full CI` stage issue as a comment with the run link,
  and is fixed there. A failure the quick profile also shows is fixed now.
- **`Full CI` and `v0.1.0 readiness` wait** for a green full run on their
  merge commit, and the release commit always needs one.
- Locally, run `gctorture(TRUE)` on the code a C change touches when it is
  cheap; the full run is the authority.

## Commits and pull requests

Short, imperative, sentence-case commit subjects, optionally scoped. Keep each
commit focused and do not sweep in unrelated files. A pull request explains the
user-visible outcome and the rationale, links related issues, lists the checks
that were run and the tests that were skipped, and flags platform-sensitive or
vendored changes. Performance claims need evidence.

Never commit or push to the default branch. Work on a branch, open a pull
request, and leave it for review. Do not merge a pull request unless you are
told to.

When you find a defect, in this package or in an upstream tool, open an issue
for it rather than only working around it.

## Working with skills

The portfolio's workflow skills live in `pedrobtz/r-skills` (`pkg-init`,
`pkg-roadmap`, `pkg-implement`, `pkg-critical-review`, `pkg-cran-review`,
`pkg-post-cran`, `pkg-readme`); the general process skills are
[Superpowers](https://github.com/obra/superpowers). `building-a-package.md`
in `pedrobtz/packages` walks through them in order. Both sets defer to this
file where they overlap, so the settlements are recorded here.

- **One design.** The specification is `.agents/design.md`, adopted from the
  package's RFC in `pedrobtz/packages/rfcs`. A package with an adopted design
  is past `brainstorming`; a design change goes through the RFC, not a new
  spec. Superpowers' default `docs/superpowers/specs/` is not used.
- **Plans at two levels.** `.agents/roadmap.md` holds the stages, one
  mergeable pull request each, with exit criteria and a CI tier
  (`pkg-roadmap`). Inside a stage, `writing-plans` breaks the work into
  tasks of one test cycle each, saved as `.agents/plans/stage-<n>.md`. The
  roadmap stays authoritative; a plan is scratch and is not kept in sync.
- **Build and merge.** `pkg-implement` runs the stage loop: branch
  `stage-<n>-<slug>` from the stage issue, implement the plan with
  `test-driven-development` (`Rscript -e 'devtools::test(filter = "<name>")'`
  is the red/green command), open the pull request, merge on green at the
  stage's CI tier. The confirmation the user gives at the start of that
  loop is the "told to merge" that Commits and pull requests requires, so
  the `finishing-a-development-branch` menu is not presented for stage
  pull requests. Any other pull request still waits for review.
- **Failures and claims.** A failing check or test goes through
  `systematic-debugging` before a fix. "Green", "done" and "ready for CRAN"
  are claimed only after `verification-before-completion`: run the command,
  read the output.
- **Review.** `requesting-code-review` gates tasks inside a stage.
  `pkg-critical-review` reviews the whole package once the roadmap is
  implemented, with Posit's reviewers, and files issues. CRAN's reviewer
  email and GitHub review threads go through `receiving-code-review`.
- **Keep scratch out of the tarball.** `R CMD build` reads `.Rbuildignore`,
  not `.gitignore`. It must list `^\.agents$`, `^\.superpowers$` (the
  Superpowers task ledger), `^\.worktrees$` (if git worktrees are kept in
  the package directory; a sibling directory avoids the question),
  `^\.claude$`, `^CLAUDE\.md$`, `^AGENTS\.md$`, `^CRAN-SUBMISSION$` and
  `^cran-comments\.md$`. A stray top-level file is a NOTE, and the pretest
  archives on NOTEs.
