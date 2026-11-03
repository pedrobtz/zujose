# zujwt: roadmap

Status: draft 2026-11-02. Implements [design.md](design.md).
Target: v0.1.0, the first CRAN release.
Tracking: [v0.1.0 (#1)](https://github.com/pedrobtz/zujwt/issues/1), with one
sub-issue per stage;
[CRAN-submission (#15)](https://github.com/pedrobtz/zujwt/issues/15).

The design calls the package `zujose`, its working name. Here and in the code
it is `zujwt`: condition classes are `zujwt_*` and `zujose_info()` is
`zujwt_info()`. The `jose_` function prefix stays.

Revised 2026-11-02: work items follow the API of design §7 as rewritten
after [the survey](api-survey.md).

This roadmap follows design §11.1 with two changes. Design Stage 6 is split
in two, so that generated keys and IVs land when `zucrypt` 0.2.0 does, without
waiting for 0.3.0. Design Stage 9 is split into documentation, `Full CI` and
`v0.1.0 readiness`, because `Full CI` carries no new work.

## Dependencies

Stages 0–5 need only `zucrypt` 0.1.0 (CRAN), `zujson` 0.1.0 (CRAN) and `zuutf`
from GitHub (`Remotes:`). Stages 6–9 each start when the named `zucrypt` stage
has merged on its `main`. Until that `zucrypt` release reaches CRAN,
`DESCRIPTION` carries `Remotes: pedrobtz/zucrypt` and requires the
development version.

| Stage | Needs | Tracked in |
| --- | --- | --- |
| 0–5 | `zuutf` 0.1.0 on CRAN before release | [zuutf#10](https://github.com/pedrobtz/zuutf/issues/10) |
| 6 | `zucrypt` Stage 13a: `crypt_rand_bytes()`, merged on its `main` 2026-11-03 | [zucrypt#9](https://github.com/pedrobtz/zucrypt/issues/9), closed by [zucrypt#83](https://github.com/pedrobtz/zucrypt/pull/83) |
| 7 | `zucrypt` Stage 14a: AES-GCM, PBKDF2, merged on its `main` 2026-11-03 | [zucrypt#10](https://github.com/pedrobtz/zucrypt/issues/10), [zucrypt#12](https://github.com/pedrobtz/zucrypt/issues/12), done in [zucrypt#84](https://github.com/pedrobtz/zucrypt/pull/84) |
| 8 | `zucrypt` Stage 15a: RSA and key I/O, merged on its `main` 2026-11-03 | [zucrypt#80](https://github.com/pedrobtz/zucrypt/issues/80), done in [zucrypt#86](https://github.com/pedrobtz/zucrypt/pull/86) |
| 9 | `zucrypt` Stage 16, v0.5.0 (candidate): EC, X25519 | [zucrypt#81](https://github.com/pedrobtz/zucrypt/issues/81) |
| 5 | Optional: AES key wrap as a `zucrypt` primitive (design D4) | [zucrypt#82](https://github.com/pedrobtz/zucrypt/issues/82) |
| 1 | Optional: strict unpadded Base64url in `zuutf` (design §8.1) | [zuutf#55](https://github.com/pedrobtz/zuutf/issues/55) |

The two optional rows don't block anything. `zujwt` composes key wrap and
padding in R until a primitive exists.

## Stages

| Stage | Title | CI | Issue | Pull request | Done |
| --- | --- | --- | --- | --- | --- |
| 0 | [Package identity](#stage-0--package-identity) | quick | [#2](https://github.com/pedrobtz/zujwt/issues/2) | [#17](https://github.com/pedrobtz/zujwt/pull/17) | 2026-11-02 |
| 1 | [Codec](#stage-1--codec) | quick | [#3](https://github.com/pedrobtz/zujwt/issues/3) | [#18](https://github.com/pedrobtz/zujwt/pull/18) | 2026-11-02 |
| 2 | [oct keys and key sets](#stage-2--oct-keys-and-key-sets) | quick | [#4](https://github.com/pedrobtz/zujwt/issues/4) | [#19](https://github.com/pedrobtz/zujwt/pull/19) | 2026-11-02 |
| 3 | [JWS with HMAC](#stage-3--jws-with-hmac) | quick | [#5](https://github.com/pedrobtz/zujwt/issues/5) | [#20](https://github.com/pedrobtz/zujwt/pull/20) | 2026-11-02 |
| 4 | [JWT](#stage-4--jwt) | full | [#6](https://github.com/pedrobtz/zujwt/issues/6) | [#21](https://github.com/pedrobtz/zujwt/pull/21) | 2026-11-02 |
| 5 | [JWE, symmetric](#stage-5--jwe-symmetric) | quick | [#7](https://github.com/pedrobtz/zujwt/issues/7) | [#22](https://github.com/pedrobtz/zujwt/pull/22) | 2026-11-02 |
| 6 | [Generated keys and IVs](#stage-6--generated-keys-and-ivs) | quick | [#8](https://github.com/pedrobtz/zujwt/issues/8) | [#23](https://github.com/pedrobtz/zujwt/pull/23) | 2026-11-03 |
| 7 | [GCM and PBES2](#stage-7--gcm-and-pbes2) | quick | [#9](https://github.com/pedrobtz/zujwt/issues/9) | [#24](https://github.com/pedrobtz/zujwt/pull/24) | 2026-11-03 |
| 8 | [RSA](#stage-8--rsa) | quick | [#10](https://github.com/pedrobtz/zujwt/issues/10) | [#25](https://github.com/pedrobtz/zujwt/pull/25) | 2026-11-03 |
| 9 | [EC and X25519](#stage-9--ec-and-x25519) | quick | [#11](https://github.com/pedrobtz/zujwt/issues/11) | | |
| 10 | [Documentation](#stage-10--documentation) | quick | [#12](https://github.com/pedrobtz/zujwt/issues/12) | | |
| 11 | [Full CI](#stage-11--full-ci) | full | [#13](https://github.com/pedrobtz/zujwt/issues/13) | | |
| 12 | [v0.1.0 readiness](#stage-12--v010-readiness) | full | [#14](https://github.com/pedrobtz/zujwt/issues/14) | | |

## Stage 0 — Package identity

**Issue.** [#2](https://github.com/pedrobtz/zujwt/issues/2), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zujwt/issues/1).

**CI.** `quick`.

**Goal.** An empty package with its real identity, dependencies, conditions and
CI, checked green.

**Work.**

- `DESCRIPTION`: real Title and Description, `Authors@R` with `cre`, `aut`,
  `cph`; `Imports: zucrypt, zujson, zuutf`; `Suggests: testthat (>= 3.0.0),
  jose`; `Remotes: pedrobtz/zuutf`; MIT; `Version: 0.0.0.9000`.
- `.Rbuildignore` with every entry the `CLAUDE.md` "Working with skills"
  section lists (done by `pkg-init`; verify).
- Condition constructors for design §9: `zujwt_error` and its subclasses
  `zujwt_parse_error`, `zujwt_policy_error`, `zujwt_key_error`,
  `zujwt_signature_error`, `zujwt_decrypt_error`, `zujwt_claim_error` and
  `zujwt_unsupported_error`, internal, with tests on class and fields.
- `R-CMD-check` caller: add the `{"os": "windows-latest", "r": "devel"}`
  runner row. Pin `coverage.yaml` to a commit, with the tag in a comment.
  Move `pkgdown.yaml` to the r-actions workflow if one exists.
- `CLAUDE.md` from the template (done by `pkg-init`).

**Deviation, 2026-11-02.** `Imports`, `Remotes` and `Suggests: jose` are
added by the stage that first calls them (Stages 1, 2 and 4), not here. An
import nothing calls is an R CMD check NOTE. `pkgdown.yaml` stays the
usethis workflow, because r-actions has no pkgdown workflow.

**Exit criteria.**

- `R CMD check` passes on the quick r-actions profile with 0 errors, warnings
  and notes, apart from "New submission".
- Every quick-profile check on the pull request finishes in under five
  minutes. Any tuning is recorded here.
- Each condition class is asserted by a test with `expect_error(class = )`.

**Design.** §9 (conditions), §11.1 Stage 0.

## Stage 1 — Codec

**Issue.** [#3](https://github.com/pedrobtz/zujwt/issues/3), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zujwt/issues/1).

**CI.** `quick`.

**Goal.** Every JOSE serialization parses into a `jose_object`, or fails with
`zujwt_parse_error`. No key is touched.

**Work.**

- Strict Base64url: alphabet and length checks, pad in R, then
  `zuutf::base64_decode(url = TRUE, forgiving = FALSE)`.
- Compact JWS and JWE, flattened and general JSON serializations.
- Header rules of §8.1: UTF-8, JSON object, no repeated member across
  protected and unprotected headers, `crit` rules.
- `jose_limits()` and the limits of §9, checked before decoding.
- `jose_peek()` returning headers, and for a JWS the payload and claims,
  classed `jose_unverified` with a print banner (D11).
- Fixtures: the RFC 7520 tokens under `tests/testthat/fixtures/` with a
  manifest recording provenance. Re-check the RFC section numbers cited in
  design §10 against the documents.
- The malformed-input corpus of §10, generated by mutating the cookbook
  tokens.

**Exit criteria.**

- Every RFC 7520 token parses; the fixture manifest names each one's source
  section.
- Every member of the malformed corpus fails with `zujwt_parse_error`.
- A token over each limit fails before any Base64 decoding (asserted with a
  mock or a counter).
- `R CMD check` green on the quick profile.

**Re-check of RFC 7520 citations, 2026-11-02.** The fixtures
(`tests/testthat/fixtures/rfc7520/MANIFEST.tsv`, from
`tools/rfc7520-fixtures.R`) give each figure's section and algorithms, and
show four citations in this roadmap were wrong:

- §4.8 (multiple signatures) mixes `RS256`, `ES512` and `HS256`; only its
  `HS256` signature belongs to Stage 3.
- §5.8 is `A128KW` with `A128GCM`, not a CBC-HS variant. No RFC 7520 vector
  uses only `dir` or `A*KW` with `A*CBC-HS*`, so Stage 5 relies on RFC 7516
  A.3, RFC 7518 B and RFC 3394.
- §5.11 and §5.12 are `A128KW` with `A128GCM` and belong to Stage 7.
  §5.9 carries `zip: "DEF"`, which zujwt rejects (§8.6).
- §5.13 (multiple recipients) needs `RSA1_5`, `ECDH-ES+A256KW` and
  `A256GCMKW`, so it completes only with Stage 9. §6 (nesting) needs `PS256`
  and `RSA-OAEP`, Stage 8.

RFC 7520 also captions Figure 41 "General JWS JSON Serialization" although
it is compact; the extraction classifies by content.

**Design.** §6 (codec layer), §8.1, §9 (limits), §10.

## Stage 2 — oct keys and key sets

**Issue.** [#4](https://github.com/pedrobtz/zujwt/issues/4), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zujwt/issues/1).

**CI.** `quick`.

**Goal.** Symmetric keys can be built, read, written, thumbprinted and selected
from a key set.

**Work.**

- `jose_key_oct()`, the `jose_key` class and a `print()` that never shows
  secret members.
- `as_jose_key()` and `as_jose_keyset()` from JWK text or lists;
  `jose_keyset()` with `[[` by kid, `[`, `c()` and `length()`;
  `jose_public()`; `jose_jwk(private = )`.
- `jose_thumbprint()` per RFC 7638 (required members only, lexicographic
  order, no whitespace, then `zucrypt::crypt_hash()`), with `uri = TRUE`
  for RFC 9278; `jose_with_kid()`.
- `kid` selection, the key-tried limit, and the `alg`, `use` and `key_ops`
  agreement checks of §8.2.
- Key resolution shared by every checking function: a key, a key set, or
  a resolver `function(header)` (D9).
- Unknown `kty` values are kept as unsupported keys, not errors, so a JWKS
  with RSA keys still loads before Stage 8.

**Exit criteria.**

- RFC 7638 §3.1, RFC 9278 and RFC 7520 §3.5 vectors pass.
- A resolver that returns a key set selects by kid (test).
- A snapshot shows `print()` of a key without its secret.
- `R CMD check` green on the quick profile.

**Design.** §8.3, §8.2 (key agreement).

## Stage 3 — JWS with HMAC

**Issue.** [#5](https://github.com/pedrobtz/zujwt/issues/5), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zujwt/issues/1).

**CI.** `quick`.

**Goal.** `jose_sign()` and `jose_verify()` work for `HS256/384/512` in all
three serializations.

**Work.**

- The policy layer of §6: the required `algorithms` argument with no
  default, key-to-algorithm binding, minimum HMAC key length.
- The algorithm table of §6, keyed by JWA name, with the `zucrypt` version
  each entry needs. `zujwt_info()` reports it.
- Signing input from the received protected header bytes; MACs compared with
  `crypt_equal()`.
- `crit` with `b64`, and RFC 7797 unencoded and detached payloads.
- General JSON: `require = "all"` by default, `"any"` on request.
- `jose_sign()` with `alg` taken from the key when `NULL`; several signers
  through `jose_signer()`; `detached = TRUE` and the `payload` argument of
  `jose_verify()` for detached payloads.
- The RFC 8725 attack tests that apply to HMAC: `alg: none`, an `HS256` token
  signed with an RSA public key's bytes, `alg` swapped within the family,
  `kid` injection, unknown `crit`, repeated header members.

**Exit criteria.**

- RFC 7515 A.1, RFC 7520 §4.4–§4.7, the `HS256` signature of §4.8, and
  RFC 7797 §4 vectors pass, verified and reproduced byte for byte.
- Each attack test fails with its documented class.
- `jose_verify()` called without `algorithms` is an error (test).
- `R CMD check` green on the quick profile.

**Design.** §6 (policy and algorithms), §7, §8.2, §8.4, §12 D2.

## Stage 4 — JWT

**Issue.** [#6](https://github.com/pedrobtz/zujwt/issues/6), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zujwt/issues/1).

**CI.** `full — first Suggests guard (the jose oracle): nosuggests`.

**Goal.** `jose_jwt_encode()` and `jose_jwt_decode()` with registered-claim
validation, interoperating with `jose` for `HS*`.

**Work.**

- Claims of §8.5: NumericDate as finite numbers, `leeway`, `now`, the
  future-`iat` check, `max_age`, `aud` as a string or array, single-string
  `issuer`, `subject` and `type`, `required = "exp"` by default (D10).
- Per-claim expectations in `claims` (a value or a predicate) and the
  whole-claims `validate` hook.
- `jose_jwt_decoder()`, the function factory of §7.5.
- `jose_claims` class, with `POSIXct` times and the header attribute.
- The claim-error leaf classes of §9.
- Nested JWS-in-JWS (`cty: "JWT"`), one level, with its own `algorithms`.
- The `jose` oracle under `skip_if_not_installed("jose")`: each package
  verifies what the other signs.

**Exit criteria.**

- RFC 7519 §3.1 and §6.1 vectors pass.
- Every claim failure raises its leaf class of `zujwt_claim_error` with the
  claim name, and times where relevant (one test each).
- An array-valued `iss` or `sub` fails even when it contains the expected
  value (test).
- The `jose` oracle passes for `HS256/384/512`.
- The full profile is green, `nosuggests` included.

**Note, 2026-11-02.** r-actions runs `nosuggests` and `nold` only when the
caller turns them on; the first full run skipped both. This stage turns
them on in `R-CMD-check.yaml`.

**Design.** §8.5, §10 (oracle).

## Stage 5 — JWE, symmetric

**Issue.** [#7](https://github.com/pedrobtz/zujwt/issues/7), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zujwt/issues/1).

**CI.** `quick`.

**Goal.** JWE with `dir` and `A128/192/256KW` over `A128/192/256CBC-HS*`.
Decryption works fully. Encryption works with an injected CEK and IV.

**Work.**

- `A*CBC-HS*` per RFC 7518 §5.2: tag verified with `crypt_equal()` before
  any CBC decryption, PKCS#7 padding removed in R.
- AES key wrap per RFC 3394, composed from one-block AES over the `_nopad`
  CBC pair (design D4).
- `jose_encrypt()` and `jose_decrypt()` with required `algorithms` and
  `encryptions`; compact and JSON serializations, one or many recipients.
- `zip` rejected (§8.6).
- Several recipients through `jose_recipient()`; `enc` defaulting to
  `A128CBC-HS256`.
- `jose_decryption()` and the `decrypt` argument of `jose_jwt_decode()`;
  a JWE given where only a JWS is allowed is a policy error (D12).
- One condition class and one message for every failure after policy (D5).

**Exit criteria.**

- RFC 7516 A.3, RFC 7518 B and RFC 3394 §4 vectors pass, decrypted and
  reproduced byte for byte.
- RFC 7520 §5.9 (`zip`) is rejected before decryption.
- One test per failure mode (wrong key, bad tag, bad padding, unwrap
  failure, length error) asserts the same class and the same message.
- `R CMD check` green on the quick profile.

**Design.** §8.6, §12 D4, D5.

## Stage 6 — Generated keys and IVs

**Issue.** [#8](https://github.com/pedrobtz/zujwt/issues/8), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zujwt/issues/1).

**CI.** `quick`.

**Blocked on** `zucrypt` Stage 13 (v0.2.0),
[zucrypt#9](https://github.com/pedrobtz/zucrypt/issues/9).
On 2026-11-03 zucrypt split its Stage 13. Randomness became Stage 13a and
merged on its `main` in
[zucrypt#83](https://github.com/pedrobtz/zucrypt/pull/83), ahead of the
0.2.0 release. This stage therefore requires `zucrypt (>= 0.1.0.9000)`,
the development version, through `Remotes:`; the bound becomes `>= 0.2.0`
when that reaches CRAN.

**Goal.** Encryption generates its own CEK and IV, so callers never supply
them.

**Work.**

- CEKs and IVs from `crypt_rand_bytes()`. The injection argument stays
  internal, for the test vectors.
- `jose_key_generate("oct")`, and `jti = TRUE` in `jose_jwt_encode()`.
- `zujwt_info()` and the unsupported-algorithm check reflect the installed
  `zucrypt` version.
- `DESCRIPTION` requires the `zucrypt` version that has randomness.

**Exit criteria.**

- Two encryptions of the same plaintext differ, and each decrypts (test).
- `jose_encrypt()` exposes no CEK or IV argument (test on `formals()`).
- `R CMD check` green on the quick profile.

**Design.** §8.6 (last item), §4.

## Stage 7 — GCM and PBES2

**Issue.** [#9](https://github.com/pedrobtz/zujwt/issues/9), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zujwt/issues/1).

**CI.** `quick`.

**Blocked on** `zucrypt` Stage 14 (v0.3.0),
[zucrypt#10](https://github.com/pedrobtz/zucrypt/issues/10) and
[zucrypt#12](https://github.com/pedrobtz/zucrypt/issues/12).
On 2026-11-03 zucrypt split its Stage 14 and shipped AES-GCM and PBKDF2 as
Stage 14a in [zucrypt#84](https://github.com/pedrobtz/zucrypt/pull/84),
ahead of 0.3.0. Because the development version still says 0.1.0.9000,
`zujwt_info()` now counts an algorithm available when zucrypt exports the
functions its release adds, not only by version. RFC 7520 §5.6's key names
`A128GCM` as its `alg` for a `dir` token, so a `dir` key may name the
token's `enc`. The RFC's whole tokens are decrypted; their encrypted keys,
not the whole tokens, are reproduced from the RFC's factors, since the
tokens' header member order is not ours.

**Goal.** `A*GCM` content encryption, `A*GCMKW` and `PBES2-*` key management.

**Work.**

- `A128/192/256GCM` and `A128/192/256GCMKW` over `zucrypt`'s AES-GCM, with a
  96-bit IV, AAD and a 128-bit tag passed explicitly.
- `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW`: the
  salt input `UTF8(alg) || 0x00 || p2s`, a `p2c` cap (default 600 000, an
  argument), `p2s` at least 8 bytes.

**Exit criteria.**

- RFC 7520 §5.3, §5.6–§5.8 and §5.10–§5.12 vectors pass.
- A `p2c` over the cap and a short `p2s` fail before any key derivation
  (tests).
- `R CMD check` green on the quick profile.

**Design.** §3, §8.6 (PBES2).

## Stage 8 — RSA

**Issue.** [#10](https://github.com/pedrobtz/zujwt/issues/10), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zujwt/issues/1).

**CI.** `quick`.

**Blocked on** `zucrypt` Stage 15 (v0.4.0, candidate),
[zucrypt#80](https://github.com/pedrobtz/zucrypt/issues/80).
zucrypt admitted the tranche and shipped what this stage needs as Stage 15a
in [zucrypt#86](https://github.com/pedrobtz/zucrypt/pull/86), on
2026-11-03. Two deviations, recorded that day: a private RSA JWK must carry
all of `p`, `q`, `dp`, `dq` and `qi` (RFC 7518 §6.3.2 lets them be
omitted; zucrypt builds keys from the full set, and the primes are not
reconstructed here); and RSA keys are kept as their JWK members, with a
zucrypt key built per operation, rather than as `zucrypt` key objects
(design §8.3), because those do not survive `saveRDS()`.

**Goal.** RSA JWKs, `RS*` and `PS*` signatures, `RSA-OAEP` and `RSA-OAEP-256`,
and opt-in `RSA1_5` decryption.

**Work.**

- RSA JWK import and export from `n`, `e` and the private members, through
  `zucrypt`'s bignum and key readers.
- PEM in `as_jose_key()`, `jose_pem()`, and `jose_key_generate("RSA")`.
- Modulus at least 2048 bits (§8.2).
- `RS256/384/512`, `PS256/384/512` (salt length equal to the hash).
- `RSA-OAEP`, `RSA-OAEP-256`; `RSA1_5` decryption only when `algorithms`
  names it, documented as Bleichenbacher-prone; never encryption.
- The `jose` oracle extended to `RS*`.

**Exit criteria.**

- RFC 7515 A.2, RFC 7520 §4.1–§4.2, §5.1–§5.2, §6 and the `RS256`
  signature of §4.8 pass.
- The `jose` oracle passes for `RS256/384/512`.
- `RSA1_5` without explicit opt-in fails with `zujwt_policy_error` (test).
- `R CMD check` green on the quick profile.

**Design.** §8.2, §8.3, §8.4.

## Stage 9 — EC and X25519

**Issue.** [#11](https://github.com/pedrobtz/zujwt/issues/11), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zujwt/issues/1).

**CI.** `quick`.

**Blocked on** `zucrypt` Stage 16 (v0.5.0, candidate),
[zucrypt#81](https://github.com/pedrobtz/zucrypt/issues/81).

**Goal.** EC and `OKP` (X25519) JWKs, `ES*` signatures, `ECDH-ES` with and
without key wrap.

**Work.**

- EC JWK import and export from `crv`, `x`, `y`, `d`; X25519 `OKP` keys;
  `jose_key_generate("EC")` and `("OKP")`.
- `ES256/384/512` with raw `r || s` signatures of fixed length per curve.
- `ECDH-ES`, `ECDH-ES+A128/192/256KW`, with the Concat KDF of RFC 7518
  §4.6.2 in R.
- The ephemeral key's curve must match the recipient's; invalid points are
  rejected.

**Exit criteria.**

- RFC 7515 A.3–A.4, RFC 7518 C, RFC 7520 §4.3, §4.8 (all three
  signatures), §5.4–§5.5 and §5.13, and RFC 8037 A.6 vectors pass.
- Invalid-curve and off-curve point tests fail closed.
- `R CMD check` green on the quick profile.

**Design.** §3, §8.3, §8.4, §8.6 (ECDH-ES).

## Stage 10 — Documentation

**Issue.** [#12](https://github.com/pedrobtz/zujwt/issues/12), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zujwt/issues/1).

**CI.** `quick`.

**Goal.** The package is documented for a user who has never read the RFCs.

**Work.**

- Roxygen for every export, with runnable examples using `oct` keys.
- `README.Rmd` (with `pkg-readme`).
- A getting-started article, and the migration article from `jose` (D7):
  one table mapping `jose` functions to `jose_*`, and the differences
  (required `algorithms`, claim checks).
- The pure-R secret-handling caveat of §8.3 in the key documentation.
- A resolver recipe for a cached JWKS fetched with `httr2` (D3, D9).
- The development-only JWE oracle job against a Python or JavaScript JOSE
  library, never at check time (§10).

**Exit criteria.**

- `devtools::document()` leaves no changes, and the pkgdown site builds.
- The oracle job has run once and its log shows JWE tokens exchanged both
  ways.
- `R CMD check` green on the quick profile.

**Design.** §7, §10 (oracle), §12 D7.

## Stage 11 — Full CI

**Issue.** [#13](https://github.com/pedrobtz/zujwt/issues/13), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zujwt/issues/1).

**CI.** `full`.

**Goal.** No new features. The full r-actions profile runs on the default
branch's code, and everything it finds is fixed.

**Work.**

- Label the pull request `full-ci`. Run every platform leg, the Windows
  R-devel row, `nosuggests`, `nold` and cran-special. gctorture, valgrind
  and ASan run but have no package C code to find fault with.
- A leg that asserts zero cookbook vectors are skipped. It is expected to
  fail while any blocked stage is open, which is what keeps the release gate
  honest.
- Fix every failure reported on this issue by earlier merges.

**Exit criteria.**

- A full-profile run is green on the pull request and on the merge commit.

**Design.** §10 (skips by capability), §14.

## Stage 12 — v0.1.0 readiness

**Issue.** [#14](https://github.com/pedrobtz/zujwt/issues/14), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zujwt/issues/1).

**CI.** `full`.

**Goal.** Only the submission itself is left.

**Entry.** The release gate of design §11.2 holds: `zuutf` is on CRAN and
`Remotes:` is dropped; `zucrypt` (>= 0.5.0) is on CRAN; zero vectors skip.

**Work.**

- `Version: 0.1.0` and the matching `NEWS.md` heading.
- `cran-comments.md` listing the r-actions CI legs as test environments.
- `pkg-critical-review`, with its blocking and required findings fixed.
- `pkg-cran-review`, with every finding resolved.
- `urlchecker::url_check()` and `spelling::spell_check_package()` clean.

**Exit criteria.**

- `DESCRIPTION` has no `Remotes:` field, and every `Imports:` package is on
  CRAN at the required version.
- The zero-skip leg passes.
- A full-profile r-actions run is green on the release commit.

**Design.** §11.2, §14.

## After 0.1.0

- `EdDSA` (RFC 8037 Ed25519): `zucrypt`'s backend has none, and gains it only
  when upstream ships it on the LTS line.
- `Ed448`, `X448`, `zip: "DEF"` and `x5c` chains: out of scope in design §3.
- A `jwt_*` compatibility layer for `jose` users: design open question 5,
  and D7 leaves it out of 0.1.0.

## Open questions

- **Stage 12, and whether CRAN is the target at all.** Is v0.1.0 a CRAN
  submission while `jose` is established, or a GitHub package for the
  no-libssl stack? The board's `CRAN intent` records the answer (design open
  question 1).
- **Stages 8, 9 and 12.** If `zucrypt` declines Stage 15 or 16, is an
  HMAC-and-symmetric release worth shipping? It covers service tokens, but
  not OIDC, where `RS256` dominates (design open question 2). The gate does
  not lower itself.
- **Stages 5 and 9.** Should `zucrypt` gain RFC 3394 key wrap and the Concat
  KDF as primitives (design open question 3)? Raised in
  [zucrypt#82](https://github.com/pedrobtz/zucrypt/issues/82).
- **Stage 8.** Does `zucrypt` Stage 15's OAEP use SHA-256 for both the label
  hash and MGF1, as `RSA-OAEP-256` needs (design open question 4)? Raised in
  [zucrypt#80](https://github.com/pedrobtz/zucrypt/issues/80).
