# RFC 0062: `zujose`, JOSE: JWS, JWE, JWK and JWT

Adopted from [RFC 0062](https://github.com/pedrobtz/packages/blob/main/rfcs/started/0062-zujose-jose-tokens.md)
on 2026-11-02. From here on this file is authoritative; the RFC is history.

The package was built as `zujwt` and renamed to `zujose`, this design's
name, on 2026-11-03. Revised 2026-11-02: §7 rewritten after the API survey, §8.5 and
§9 extended to match, D9–D12 added.

- **Status:** Proposed. Section 12 records decisions for the package's
  future design document. The release gate in section 11.2 is the one
  most worth a second look: the package is quick to start and slow to
  ship, because its public-key algorithms wait on `zucrypt` tranches that
  are candidates, not commitments.
- **Date:** 2026-11-01.
- **Packages:** `zujose` (not yet created; crandb returns `not_found` and
  there is no `pedrobtz/zujose` repository, both checked on 2026-11-01).
  Pure R, no `src/`, no `LinkingTo`. `Imports: zucrypt, zujson, zuutf`.
  `Suggests: testthat, jose`. MIT.
- **Source:** RFCs 7515–7520, 7638, 7797, 8037 and 8725, cited as
  references, not re-read for this draft; `pedrobtz/zucrypt`'s
  `.agents/design.md` (revision 4), `.agents/roadmap.md`, `NAMESPACE`
  and open issues on `main`;
  `pedrobtz/zuutf`'s design §5–§6, `NAMESPACE` and stage issues;
  `pedrobtz/zujson`'s `NAMESPACE` and `R/parse.R`; `jose` 2.0.0's
  crandb record and its `NAMESPACE` and `R/` sources on GitHub; crandb
  reverse dependencies of `jose`, all read on 2026-11-01. No token was
  signed, verified or decrypted for this draft.

## 1. What zujose is

`zujose` signs, verifies, encrypts and decrypts JOSE objects: JSON Web
Signatures (JWS), JSON Web Encryption (JWE), JSON Web Keys and key sets
(JWK, JWKS), and JSON Web Tokens (JWT) built on them. It covers both the
compact and the JSON serializations, and claim validation for JWTs.

Users are R code that talks to OAuth 2.0 and OpenID Connect providers,
cloud APIs that take signed assertions (service accounts, GitHub Apps),
ACME clients, and Shiny or Plumber services that issue or check tokens.

> **The caller names the algorithms it accepts; the token never chooses
> them.**

It contains no cryptography. Every primitive comes from `zucrypt`,
Base64url from `zuutf`, and JSON from `zujson`. What `zujose` owns is the
JOSE layer: serializations, header rules, key representation, algorithm
policy and claim checks. Most JOSE failures in practice are failures of
that layer (RFC 8725 §2), which is why it deserves a package of its own.

### 1.1 What zujose is not

- Not an OAuth or OIDC client. Discovery, token endpoints and refresh
  belong to `httr2` or `zuhttp`.
- Not a key store. Keys live in the caller's memory; nothing is cached.
- Not a fetcher. `jku`, `x5u` and embedded `jwk` header values are never
  dereferenced or trusted as keys.

## 2. Where it sits among existing CRAN packages

`jose` 2.0.0 (Jeroen Ooms, published 2026-04-22) is the established
package. It depends on `openssl` (>= 1.2.1) and imports `jsonlite`. It
reads and writes JWKs for RSA, EC, Ed25519 and `oct` keys, encodes and
decodes compact JWTs with `HS*`, `RS*`, `ES*` and `EdDSA`, and checks
`exp` and `nbf` with a fixed 60-second allowance. It has 20 reverse
`Imports` and 7 reverse `Suggests` on crandb, among them `httr2`,
`AzureAuth`, `boxr`, `ghapps` and `shinyOAuth`. `httr2` also exports its
own `jwt_claim()`, `jwt_encode_hmac()` and `jwt_encode_sig()`.

`jose` works and is widely used; this RFC does not claim it is unsafe.
Its sources separate HMAC from public-key decoding into two functions,
which already blocks the classic `HS256`-with-a-public-key confusion.
What it does not do, read from its `NAMESPACE` and `R/` on 2026-11-01:

1. **JWE.** No encryption or decryption of any kind.
2. **PS256/384/512**, `RSA-OAEP`, `ECDH-ES` and the JSON serializations.
3. **Explicit allow-lists.** Within a key family the header's `alg`
   decides the hash; there is no `algorithms =` argument.
4. **Audience, issuer and type checks**, RFC 8725 §3.8–§3.11; the caller
   checks `aud`, `iss` and `typ` by hand.
5. **RFC 7638 thumbprints**, `crit`, and RFC 7797 unencoded payloads.

What `zujose` would add is therefore:

- No system library. `openssl` needs system libssl on Linux; `zucrypt`
  vendors its backend, so the whole stack installs with a C compiler.
- JWE, with the RFC 7518 algorithm set that the backend can support.
- RFC 8725 defaults: required allow-lists, key-to-algorithm binding,
  explicit typing, audience and issuer checks, no `none`, no compression.
- One API in the family's style, with structured conditions.

What it gives up: Ed25519 (section 4), maturity, and `jose`'s reverse
dependencies, none of which would move. Whether that is enough for a CRAN
submission is the board's `CRAN intent` and open question 1.

## 3. Scope

In v0.1.0, subject to the dependency table of section 4:

- JWS compact, flattened JSON and general JSON serializations; `crit`;
  RFC 7797 `b64: false` for detached and unencoded payloads.
- JWS algorithms `HS256/384/512`, `RS256/384/512`, `PS256/384/512` and
  `ES256/384/512`.
- JWE compact and JSON serializations, one or many recipients, with
  `A128/192/256CBC-HS256/384/512` and `A128/192/256GCM` content
  encryption.
- JWE key management `dir`, `A128/192/256KW`, `A128/192/256GCMKW`,
  `PBES2-HS256+A128KW` and its siblings, `RSA-OAEP`, `RSA-OAEP-256`,
  `ECDH-ES` and `ECDH-ES+A128/192/256KW`, on P-256/384/521 and X25519.
- JWK and JWKS for `oct`, `RSA`, `EC` and `OKP` (X25519 only); RFC 7638
  thumbprints; selection by `kid` from a caller's key set.
- JWT encode and decode with registered-claim validation and nested JWTs.

Out of scope for v0.1.0: `EdDSA` (section 4), `Ed448` and `X448`;
`RSA1_5` encryption (decryption only, behind an explicit opt-in);
`zip: "DEF"`; X.509 chains in `x5c`; and `none` in either direction.

## 4. What the dependencies provide, and when

This table decides the roadmap. `zucrypt` 0.1.0 was published on
2026-10-23; its `NAMESPACE` on `main` exports seven functions:
`crypt_hash()`, `crypt_hmac()`, `crypt_hex()`, `crypt_equal()`,
`crypt_info()` and the CBC pair `crypt_aes_cbc_encrypt_nopad()` and
`_decrypt_nopad()`. Its roadmap (Part A, "Stage map") places the rest:

| `zujose` needs | `zucrypt` provides it in | Status on 2026-11-01 |
| --- | --- | --- |
| SHA-2, HMAC, constant-time compare | 0.1.0 | on CRAN |
| AES block for CBC-HS and AES-KW | 0.1.0, CBC without padding | on CRAN |
| Random bytes for CEKs, IVs, salts | Stage 13, v0.2.0 (#9) | not started |
| AES-GCM | Stage 14, v0.3.0 (#10) | not started |
| PBKDF2 | Stage 14, v0.3.0 (#12) | not started |
| RSA keys, PKCS#1, PSS, OAEP, bignum | Stage 15, v0.4.0 | candidate |
| EC keys, ECDSA, ECDH, X25519 | Stage 16, v0.5.0 | candidate |
| Ed25519 | none: "a documented gap" | not in backend |

Three corrections to the premise this RFC was asked to start from:

- **RSA and EC are `zucrypt` Stages 15 and 16**, releases 0.4.0 and
  0.5.0, not a "Stage 6". Stage 6 is the old v0.1.0 tag in the
  roadmap's Part B, superseded by Stage 12.
- **Both are candidates.** Each opens with an admission decision under
  `zucrypt`'s criterion 5 once the tranche before it has shipped. The
  roadmap names `jose` among the four importers that need `crypt_bignum()`
  and as one of two that need Ed25519, so `zujose` is itself evidence for
  that decision, but it is not a commitment.
- **There is no EdDSA, now or planned.** The pinned TF-PSA-Crypto 1.1 has
  X25519 but no Ed25519; it enters "when upstream ships
  `PSA_WANT_ALG_PURE_EDDSA` on the LTS line, or not at all".
  So RFC 8037's `EdDSA` is out of v0.1.0, and `OKP` means X25519 only.

Even GCM and randomness are not there yet: `zucrypt` is preparing 0.1.1
(#77), and issues #9, #10 and #12 are open. What *is* buildable today is
`HS*`, `dir` and `A*KW` with `A*CBC-HS*`, `oct` keys and thumbprints.
JWE encryption works only with a supplied CEK and IV until 0.2.0.

**Amended 2026-11-12.** `zucrypt` re-planned its releases (its roadmap,
"Re-planned 2026-11-12"). It split Stages 13a to 16a off its tranches
for this package; all four are done, and they ship together in
`zucrypt` 0.1.1: randomness, SHA-2 as named functions, AES-GCM, PBKDF2,
RSA and key I/O, EC keys, ECDSA, ECDH and X25519. Every primitive in the
table above beyond HMAC and AES-CBC, Ed25519 apart, is therefore in
0.1.1, and `zujose` needs `zucrypt` (>= 0.1.1) for every algorithm. The
tranche releases 0.2.0 to 0.5.0 remain `zucrypt`'s plans for its own
broader API; `zujose` no longer waits on them.

`zuutf` 0.1.0 has closed all eight stages (#2–#9); its `v0.1.0` issue (#1)
and `CRAN-submission` issue (#10) are open, and crandb returns
`not_found`. It exports `base64_encode(x, url, pad, line_length)` and
`base64_decode(x, url, forgiving, pad)`. Its strict mode (`forgiving =
FALSE`) rejects whitespace and non-zero trailing bits; with `pad = FALSE`
it also refuses padding, which JOSE forbids (zuutf#55, 2026-11-03; it
required padding before, and `zujose` padded the text in R).

`zujson` 0.1.0 is on CRAN (2026-10-02) with `json_parse()`,
`json_parse_raw()`, `json_write()` and `json_validate()`. Plain parsing
keeps a repeated object key as two list elements, so `zujose` can detect
duplicates itself. Numbers outside 32-bit integers arrive as `double`,
which holds NumericDate values exactly to 2^53.

## 5. Position in the family

- **`zucrypt`:** every primitive, through its exported R functions only.
  `zujose` never touches its C archive or table, so none of the ABI
  freeze rules apply here.
- **`zuutf`:** Base64url and UTF-8 validation of decoded header bytes.
- **`zujson`:** parsing and writing headers, claims and JWKs. Canonical
  member ordering for RFC 7638 is done in `zujose`, not asked of `zujson`.
- **`zuhttp`:** a future caller (bearer tokens, signed assertions). It
  stays optional; `zujose` performs no I/O.
- **`zutempo`:** not used. NumericDate is seconds as `double`;
  `POSIXct` is accepted and returned at the boundary.

## 6. Architecture

Three layers, all R:

1. **Codec.** Split, Base64url-decode and parse the parts of a compact or
   JSON serialization into a `jose_object`: protected header bytes and
   parsed list, unprotected headers, payload or ciphertext parts, and
   per-signature or per-recipient entries. No key is touched here.
2. **Policy.** Check the object against the caller's `algorithms`,
   `crit`, size limits and key set before any cryptographic call. A
   rejected header never reaches `zucrypt`.
3. **Algorithms.** One small R function per JWA identifier, registered in
   an internal table keyed by name, with the `zucrypt` version it needs.
   An identifier whose function is missing from the installed `zucrypt`
   is reported as unsupported, never silently skipped.

Signing input and AAD are always built from the *received* protected
header bytes, never from a re-serialized header. Constructions that JWA
defines over primitives (`A*CBC-HS*` per RFC 7518 §5.2, AES key wrap per
RFC 3394, Concat KDF per RFC 7518 §4.6.2) are written in R over
`zucrypt` calls and are tested against their RFC vectors.

## 7. Public R API

*Revised 2026-11-02 after a survey of three Go and four Python JOSE
libraries: PyJWT, joserfc, jwcrypto, python-jose, go-jose v4, golang-jwt v5
and lestrrat-go/jwx. The survey is in [api-survey.md](api-survey.md). The
features match the best of them. The shape is R's: functions rather than
builders, S3 classes with `print()` and `as_*()` coercions, named arguments,
and closures for reuse.*

### 7.1 Conventions

- **Named after the object.** `jwt_*` for JSON Web Tokens, `jws_*` for
  signatures, `jwe_*` for encryption and `jwk_*` for keys and key sets.
  Functions that apply to any JOSE object take `jose_` (`jose_peek()`,
  `jose_limits()`), and package-level helpers take the package name
  (`zujose_info()`). No name equals one of `jose`'s exports (`jwt_claim`,
  `jwt_encode_hmac`, `jwt_decode_sig`, `jwt_split`, `jwk_read`,
  `jwk_write`, ...), which is why a key is written by `jwk_json()`.
  Classes follow the functions: `jwk`, `jwk_set`, `jws_verified`,
  `jwe_decrypted`, `jwt_claims`. (2026-11-03: replaces one `jose_` prefix
  on every function, before any release.)
- **Data first**, so calls chain with `|>`: the token, payload or claims
  is the first argument, the key the second.
- **Types at the boundary.** Tokens and JWK text are character scalars.
  Payloads and plaintexts are raw vectors, or a single string taken as
  UTF-8 text, never as Base64 or hex. Results return raw. Headers and
  claims are named lists. Times are `POSIXct` in and out; NumericDate
  stays inside.
- **No default where the argument decides trust.** `algorithms`,
  `encryptions` and `key` have none in any function that accepts a token.
  Elsewhere defaults are the safe common case.
- **Nothing unverified hides behind a flag.** There is no
  `verify = FALSE`. Reading a token without checking it is a separate
  function, `jose_peek()`, whose result is classed `jose_unverified` and
  prints a warning banner.
- **Reuse through closures.** A function factory captures a policy once,
  as golang-jwt's `NewParser()` and joserfc's registries do.

### 7.2 Keys and key sets

```r
key <- jwk_oct(secret, alg = "HS256", kid = NULL, use = NULL,
                    key_ops = NULL)
key <- jwk_generate("oct", size = 256, alg = "HS256")     # Stage 6
key <- jwk_generate("RSA", size = 2048, alg = "RS256")    # Stage 8
key <- jwk_generate("EC", crv = "P-256", alg = "ES256")   # Stage 9
key <- as_jwk(x)       # JWK text, a parsed JWK list, or PEM (Stage 8)
key <- jwk_with_kid(key)   # kid defaults to the RFC 7638 thumbprint

ks  <- jwk_set(key1, key2)
ks  <- as_jwk_set(jwks) # JWKS text or a parsed list
ks[["k1"]]                  # by kid; c(), length() and [ work too

jwk_public(key_or_set)     # public part; drops oct keys from a set
jwk_json(key_or_set, private = FALSE)   # JWK or JWKS text
jwk_pem(key, private = FALSE)          # Stage 8
jwk_thumbprint(key, hash = "sha256", uri = FALSE)  # RFC 7638, RFC 9278
```

`as_jwk_set()` keeps keys of a type the installed `zucrypt` cannot use
as unsupported entries rather than failing, so a provider's JWKS loads
before the matching stage lands. Using such a key raises
`zujose_unsupported_error`.

Wherever a function takes a key to check a token, it accepts a `jwk`,
a `jwk_set`, or a **resolver**: `function(header)` returning a key or
key set. The resolver is the explicit way to choose keys per issuer, or to
honour `jku` against an allow-list the caller writes. `zujose` itself still
never fetches anything (D3). The getting-started article shows a JWKS
cache with `httr2` behind a resolver.

### 7.3 JWS

```r
tok <- jws_sign(payload, key, alg = NULL, header = NULL,
                 unprotected = NULL,
                 format = c("compact", "flattened", "general"),
                 b64 = TRUE, detached = FALSE)

tok <- jws_sign(payload, list(jws_signer(k1, "RS256"),
                               jws_signer(k2, "ES256")),
                 format = "general")

v <- jws_verify(tok, key, algorithms, payload = NULL,
                 require = c("all", "any"), limits = jose_limits())
v$payload; v$header; v$kid; v$alg
```

`alg = NULL` takes the key's own `alg` and fails when it has none. `header`
is the protected header, `unprotected` the per-signature one. `payload` in
`jws_verify()` supplies a detached payload. `b64 = FALSE` writes RFC 7797
with `crit: ["b64"]`. The result has class `jws_verified`.

### 7.4 JWE

```r
tok <- jwe_encrypt(plaintext, key, alg = NULL, enc = "A128CBC-HS256",
                    header = NULL, unprotected = NULL, aad = NULL,
                    format = c("compact", "flattened", "general"))

tok <- jwe_encrypt(plaintext, list(jwe_recipient(k1, "RSA-OAEP-256"),
                                    jwe_recipient(k2, "ECDH-ES+A256KW")),
                    enc = "A256GCM", format = "general")

d <- jwe_decrypt(tok, key, algorithms, encryptions,
                  limits = jose_limits())
d$plaintext; d$header; d$kid; d$alg; d$enc
```

`enc` defaults to `A128CBC-HS256`, the content encryption RFC 7518 §5.1
marks required, and the one available from Stage 5. PBES2 parameters go in
`header` (`p2c`); the salt is generated. The result has class
`jwe_decrypted`.

### 7.5 JWT

```r
jwt <- jwt_encode(claims, key, alg = NULL,
                       header = list(typ = "JWT"),
                       expires_in = NULL, not_before = NULL,
                       issued_at = TRUE, jti = FALSE)

cl <- jwt_decode(jwt, key, algorithms,
                      audience = NULL, issuer = NULL, subject = NULL,
                      type = "JWT", required = "exp", claims = list(),
                      validate = NULL, max_age = NULL, leeway = 60,
                      now = Sys.time(), decrypt = NULL,
                      limits = jose_limits())

check <- jwt_decoder(key = jwks, algorithms = "RS256",
                          audience = "my-api",
                          issuer = "https://issuer.example")
cl <- check(jwt)                         # same checks, every call
```

- `claims` holds per-claim expectations. A value must match exactly. A
  function, such as `\(scope) "read" %in% strsplit(scope, " ")[[1]]`, must
  return `TRUE`. Either way the claim must be present. `validate` is one
  function of the whole claim list, for checks across claims.
- `expires_in` and `not_before` take seconds or a `difftime`. `claims` may
  hold `POSIXct` values for `exp`, `nbf` and `iat`. `jti = TRUE` adds a
  random identifier (Stage 6).
- An encrypted JWT is composed rather than flagged:
  `jwt_encode(...) |> jwe_encrypt(k2, header = list(cty = "JWT"))`.
  `jwt_decode()` accepts one only when given
  `decrypt = jwe_decryption(key, algorithms, encryptions)`. Without it a
  JWE token is a policy error, which closes the JWS/JWE confusion of
  jwcrypto's CVE-2022-3102.
- The result has class `jwt_claims`: the claims as a named list, with
  `exp`, `nbf` and `iat` as `POSIXct` and the verified header as an
  attribute.

### 7.6 Inspection and limits

```r
jose_peek(tok)       # every part decoded: headers, payload, claims, signatures
                     # or encrypted keys, IV, ciphertext, tag, AAD; unverified
jose_limits(token = 2^21, header = 2^14, payload = 2^20, signatures = 16,
            recipients = 16, keys = 16, p2c = 600000)
zujose_info()         # data frame: algorithm, kind, available, zucrypt needed
```

### 7.7 Against the surveyed libraries

Each `zujose` feature, and the libraries it matches:

- **Mandatory allow-list** (`algorithms`, no default): go-jose v4,
  PyJWT 2.
- **Key, key set or resolver** (§7.2): joserfc's callable, golang-jwt's
  `Keyfunc`, jwx's `KeyProvider`.
- **Multiple signers or recipients** (`jws_signer()`,
  `jwe_recipient()`): jwx's repeated `WithKey`, go-jose's
  `NewMultiSigner`.
- **Detached and unencoded payloads** (`detached`, `b64`, `payload`): jwx
  `WithDetachedPayload`, go-jose `DetachedVerify`.
- **Claim expectations and validators** (`claims`, `validate`): jwx
  `WithClaimValue` and `WithValidator`, joserfc's claims registry.
- **Subject, maximum age, future `iat`** (`subject`, `max_age`, always
  on): golang-jwt `WithSubject` and `WithIssuedAt`, jwx `WithMaxDelta`.
- **Reusable policy** (`jwt_decoder()`): golang-jwt `NewParser`,
  joserfc registries.
- **Unverified inspection** (`jose_peek()`): PyJWT
  `get_unverified_header`, jwx `ParseInsecure`.
- **Key generation and public part** (`jwk_generate()`,
  `jwk_public()`): joserfc `generate_key`, go-jose `Public()`.
- **Thumbprint, thumbprint URI, kid** (`jwk_thumbprint()`,
  `jwk_with_kid()`): joserfc `thumbprint_uri` and `ensure_kid`.

Left out on purpose: JWKS fetching and caching (PyJWT `PyJWKClient`, jwx
`jwk.Cache`), replaced by a resolver recipe (D3); and `zip`, `none`,
EdDSA and ES256K (§3).

## 8. Semantics and security defaults

### 8.1 Parsing

- Base64url is decoded with `base64_decode(url = TRUE, forgiving = FALSE,
  pad = FALSE)`, which rejects padding, whitespace, the standard alphabet,
  a one-character final quantum and non-canonical trailing bits, so every
  token has one encoding.
- Decoded headers must be valid UTF-8 and a JSON object with no repeated
  member name across protected and unprotected headers (RFC 7515 §4,
  RFC 7516 §4; rejection rather than "last wins", per RFC 8725 §3.4).
- `crit` lists only names that `zujose` implements (`b64`); anything else
  fails, as does a `crit` naming a registered header or appearing
  unprotected.

### 8.2 Algorithm policy

- The caller's `algorithms` (and `encryptions`) are matched exactly. The
  header's `alg` must be in the list *and* agree with the key: `HS*` only
  with `oct`, `RS*`/`PS*` only with `RSA`, `ES256` only with P-256 and so
  on. A JWK's own `alg`, `use` and `key_ops`, when present, must agree.
- `none` is not implemented. There is no flag that enables it.
- Minimum key strength is enforced: HMAC keys at least the hash output
  (RFC 7518 §3.2), RSA moduli at least 2048 bits (§3.3), AES-KW and `dir`
  keys of exactly the size the identifier names.
- `RSA1_5` decryption needs `algorithms` to name it explicitly and is
  documented as Bleichenbacher-prone (RFC 8725 §3.2); it never encrypts.

### 8.3 Keys

A `jwk` is an R list of class `jwk` with `kty`, the key
material as raw or `zucrypt` key objects, and optional `kid`, `alg`,
`use` and `key_ops`. Printing never shows secret members. Public RSA and
EC JWKs convert to `zucrypt` key objects through `crypt_bignum()` and
`zucrypt`'s key readers once they exist. Thumbprints follow RFC 7638:
required members only, lexicographic order, no whitespace, then
`crypt_hash()`.

Key selection: with a key set, a token's `kid` picks candidates; without
a `kid`, every key compatible with the header's `alg` is tried, up to a
limit. Keys embedded in the token (`jwk`, `x5c`) or referenced by URL
(`jku`, `x5u`) are never used.

Secrets live in ordinary R vectors. Pure R cannot wipe memory or avoid
copies; the documentation says so rather than implying otherwise.

### 8.4 JWS

Signing input is `ASCII(BASE64URL(protected) || "." || payload)`, with
the payload unencoded when the protected header carries `b64: false`
(RFC 7797, which also requires `crit: ["b64"]`). MACs are compared with
`crypt_equal()`. ECDSA signatures are raw `r || s` of fixed length per
curve (RFC 7518 §3.4), which `zucrypt` Stage 16 says its backend
produces natively. PSS uses a salt the length of the hash. In a general
JSON serialization, `jws_verify()` succeeds only when every signature
verifies unless `require = "any"` is given.

### 8.5 JWT claims

`exp`, `nbf` and `iat` are NumericDate and must be finite numbers; a
string or `NA` is a malformed token, not a skipped check. Expiry and
not-before use `leeway` seconds (default 60, as jwcrypto and go-jose)
against `now`. An `iat` later than `now + leeway` fails, and `max_age`,
when given, bounds `now - iat`.

`required` defaults to `"exp"`: a token that never expires must be accepted
on purpose, with `required = character()`. `aud` may be a string or an
array; it matches when it contains any of `audience`. A token that carries
`aud` fails when the caller passes no `audience` (RFC 7519 §4.1.3), and one
without `aud` fails when the caller does (RFC 8725 §3.9). `issuer`,
`subject` and `type` are exact single-string matches. An array-valued `iss`
or `sub` is a claim error, never a membership test: PyJWT
(CVE-2024-53861) and joserfc (CVE-2026-75509) were both caught by looser
matching. A nested JWT (`cty: "JWT"`) is unwrapped one level only: a signed
JWT inside a JWE, with a separate allow-list for each layer, the
`jwe_decryption()` object's for the JWE and `algorithms` and `key` for the
signature. A signed JWT inside a signed JWT, and any deeper nesting, is a
`zujose_policy_error`, decided on the header before any signature is
checked; a caller who needs one calls `jws_verify()` twice. Go-jose and
Nimbus nest the same way, and jwcrypto and panva `jose` do not unwrap at
all (Amended 2026-11-12, #46). An encrypted-only JWT, a JWE carrying
the claims set itself, is accepted only with symmetric key management
(`dir`, `A*KW`, `A*GCMKW`, `PBES2-*`): with RSA or ECDH key management
anyone holding the recipient's public key can make one, so its claims
would be unauthenticated. Such a token is refused with
`zujose_policy_error` before decryption, and there is no flag to accept
it (2026-11-03, #34).

### 8.6 JWE

- Every decryption failure after header policy (wrong key, bad tag, bad
  padding, unwrap failure, length errors) raises one condition class with
  one message, so the error is not an oracle (RFC 7516 §11.5).
- `A*CBC-HS*` verifies the HMAC tag with `crypt_equal()` over AAD, IV,
  ciphertext and AL before any CBC decryption, then removes PKCS#7
  padding in R (RFC 7518 §5.2.2.2).
- AES key wrap (RFC 3394) is built on the one-block AES operation that
  `crypt_aes_cbc_encrypt_nopad()` with a zero IV gives, until `zucrypt`
  offers a key-wrap function (decision D4).
- PBES2 caps `p2c` (default 600 000, an argument) to bound the cost an
  attacker can impose, and rejects `p2s` shorter than 8 bytes.
- `ECDH-ES` checks that the ephemeral key's curve is the recipient key's
  and relies on `zucrypt`'s point validation (RFC 8725 §3.4).
- `zip` in any header is rejected (RFC 8725 §3.6).
- Encryption generates the CEK, IV and salts with `crypt_rand_bytes()`.
  Tests inject them through an internal argument to reproduce RFC 7520.

## 9. Errors and limits

Conditions inherit from `zujose_error`: `zujose_parse_error`,
`zujose_policy_error` (algorithm not allowed, `crit`, key mismatch, a JWE
where none was allowed), `zujose_key_error`, `zujose_signature_error`,
`zujose_decrypt_error` and `zujose_claim_error`.
`zujose_unsupported_error` names the `zucrypt` version an algorithm needs.

`zujose_claim_error` has leaf classes, so callers branch on the cause as
PyJWT's do: `zujose_expired_error`, `zujose_not_yet_valid_error`,
`zujose_audience_error`, `zujose_issuer_error`, `zujose_subject_error` and
`zujose_missing_claim_error`. Each carries the claim name, and the time
errors carry both times. Messages name claims and times but never echo
key material, decrypted bytes or token text (joserfc CVE-2025-65015).

`jose_limits()` caps token length (2 MiB, as the encoded form is about
4/3 of the payload), header length (16 KiB), payload length including
detached and `b64: false` payloads (1 MiB; joserfc CVE-2026-48990 missed
that path), signatures and recipients per JSON object (16), keys tried
per token (16) and PBES2 iterations (600 000).
Each is checked before decoding. Encoders do not check the limits, which
guard untrusted input.

## 10. Testing

- **Vectors with provenance**, committed under `tests/testthat/fixtures/`
  with a manifest: RFC 7520 (the JOSE cookbook) in full for what the
  installed `zucrypt` supports; RFC 7515 Appendix A, RFC 7516 Appendix A,
  RFC 7518 Appendix B (CBC-HS) and C (ECDH-ES); RFC 7519 §3.1 and §6.1;
  RFC 7638 §3.1; RFC 7797 §4; RFC 8037 Appendix A.6 (X25519); RFC 3394
  §4 for key wrap.
- **Skips by capability.** A vector needing an algorithm the installed
  `zucrypt` lacks is skipped with the version named; one CI leg asserts
  that zero vectors are skipped before release.
- **Oracle.** PyJWT, through fixtures written offline by
  `tools/make-oracle-fixtures.py`: JWTs it signs with `HS*`, `RS*`, `PS*`
  and `ES*`, and the PEM keys (from `cryptography`) that sign them.
  zujose verifies each, and reproduces the deterministic `HS*` and `RS*`
  signatures byte for byte. JWE has no oracle at check time; a
  development-only job checks against a Python or JavaScript JOSE library.
  (2026-11-03: replaces `jose` and `openssl` in `Suggests`, so the suite
  needs no other JOSE implementation installed.)
- **RFC 8725 attacks** as named tests: `alg: none`, `HS256` signed with
  an RSA public key's bytes, `alg` swapped within a family, `kid`
  injection, `crit` with unknown names, repeated header members, invalid
  curve points, huge `p2c`, truncated tags, and each JWE failure mode
  asserting the same condition and message.
- **Malformed input** generated by mutating every part of the cookbook
  tokens: wrong part count, padding, whitespace, non-UTF-8, non-object
  JSON, oversize parts.

## 11. Roadmap

### 11.1 Stages

Stages run the quick r-actions profile unless marked `full`. Stages 0–5
need only `zucrypt` 0.1.0 and `zuutf` from GitHub; Stages 6–8 each start
when the named `zucrypt` stage has merged on its `main`.

- **Stage 0: package identity.** Scaffold, `r-cmd-check.yml` from
  `pedrobtz/r-actions`, `Remotes:` for `zuutf`, conditions. Exit: CI
  green on an empty package.
- **Stage 1: codec.** Base64url, compact and JSON serializations, header
  rules of section 8.1, `jose_peek()`, limits. Exit: every RFC 7520
  token parses; the malformed corpus fails with `zujose_parse_error`.
- **Stage 2: `oct` keys and key sets.** `jwk()`, JWK and JWKS read
  and write, RFC 7638 thumbprints, `kid` selection. Exit: RFC 7638 and
  RFC 7520 §3.5 vectors.
- **Stage 3: JWS with `HS*`.** Sign, verify, all three serializations,
  `crit`, RFC 7797. Exit: RFC 7515 A.1, RFC 7520 §4.4–§4.8 and RFC 7797
  vectors; the RFC 8725 attack tests for HMAC.
- **Stage 4: JWT.** Claims, validation of section 8.5, nested tokens.
  Exit: RFC 7519 vectors, every claim failure classed, `jose` oracle
  green for `HS*`.
- **Stage 5: JWE, symmetric.** `dir` and `A*KW` with `A*CBC-HS*`;
  decryption, and encryption with injected CEK and IV. Exit: RFC 7516
  A.3, RFC 7518 B, RFC 3394 and RFC 7520 §5.8 (CBC-HS variant) vectors;
  uniform JWE failure.
- **Stage 6: randomness, GCM and PBES2.** *Blocked on `zucrypt`
  Stages 13 and 14 (v0.2.0, v0.3.0).* Generated CEKs and IVs, `A*GCM`,
  `A*GCMKW`, `PBES2-*`. Exit: RFC 7520 §5.3, §5.6–§5.8 and §5.10.
- **Stage 7: RSA.** *Blocked on `zucrypt` Stage 15 (v0.4.0, candidate).*
  RSA JWKs, `RS*`, `PS*`, `RSA-OAEP`, `RSA-OAEP-256`, `RSA1_5` opt-in
  decryption. Exit: RFC 7515 A.2, RFC 7520 §4.1–§4.2 and §5.1–§5.2;
  `jose` oracle for `RS*`.
- **Stage 8: EC and X25519.** *Blocked on `zucrypt` Stage 16 (v0.5.0,
  candidate).* EC and `OKP` X25519 JWKs, `ES*`, `ECDH-ES` with and
  without key wrap, Concat KDF. Exit: RFC 7515 A.3–A.4, RFC 7518 C,
  RFC 7520 §4.3 and §5.4–§5.5, RFC 8037 A.6; invalid-curve tests.
- **Stage 9 (`full`): Full CI.** The full r-actions set, the
  development-only JWE oracle job, documentation, a migration article
  from `jose`. `full` because it is the first run of the whole set and
  fixes what it finds. Exit: section 14.

### 11.2 The release gate

`zujose` 0.1.0 is not submitted to CRAN until all of these hold:

1. `zuutf` is on CRAN, so `Remotes:` can be dropped.
2. `zucrypt` (>= 0.1.1) is on CRAN, with randomness, AES-GCM, PBKDF2,
   RSA, PSS, OAEP with SHA-256, ECDSA, ECDH and X25519, so Stages 6–8
   can ship. (It read `>= 0.5.0` before `zucrypt`'s 2026-11-12
   re-plan; see section 3.)
3. Zero cookbook vectors skip on the release leg.

Until then the package is usable from GitHub with the subset that
`zujose_info()` reports. If `zucrypt` declines tranche 3 or 4, the gate
does not quietly lower itself: the maintainer decides between a
symmetric-only release and waiting (open question 2).

## 12. Proposed decisions

- **D1.** No compiled code; every primitive is a `zucrypt` call, and
  JWA constructions over primitives are R code tested against RFC vectors.
- **D2.** `algorithms` is required wherever a token is trusted, and the
  key must agree with the algorithm; `none` is never implemented.
- **D3.** Keys come only from the caller; header-embedded or referenced
  keys are ignored, and `zujose` performs no network access.
- **D4.** AES key wrap is composed from one-block AES over the `_nopad`
  CBC pair now, and replaced by a `zucrypt` function if one is admitted.
- **D5.** All JWE decryption failures share one class and message.
- **D6.** Base64url decoding is strict and canonical, through `zuutf`'s
  strict unpadded mode (`forgiving = FALSE, pad = FALSE`).
- **D7.** Functions are named after their object (`jwt_*`, `jws_*`,
  `jwe_*`, `jwk_*`; §7.1), with no `jose`-compatible mirror layer in
  0.1.0; a migration article instead.
- **D8.** The release waits for the gate of section 11.2; Stages 0–5 are
  built now on `zucrypt` 0.1.0 so that the JOSE layer is done and tested
  before the public-key tranches arrive.
- **D9.** Every function that checks a token takes a key, a key set or a
  resolver `function(header)`. Resolvers are how callers opt into
  per-issuer keys or `jku`; `zujose` never does either itself.
- **D10.** Claim checks happen inside `jwt_decode()`, never as a
  second step a caller can forget (joserfc's split is the counterexample).
  `required` defaults to `"exp"`.
- **D11.** Unverified reading is one separately named function,
  `jose_peek()`; no `verify` or `verify_*` flags exist.
- **D12.** A JWE is accepted where a JWT is expected only with an explicit
  `decrypt = jwe_decryption(...)`.

## 13. Open questions

1. Is v0.1.0 a CRAN submission with `jose` established, or a GitHub
   package for the no-libssl stack? The board's `CRAN intent` records it.
2. If `zucrypt` does not admit Stages 15 or 16, is an HMAC-and-symmetric
   JWE release worth shipping? It would cover service tokens but not
   OIDC, where `RS256` dominates.
3. Should `zucrypt` gain RFC 3394 key wrap and RFC 7518's Concat KDF as
   primitives, rather than `zujose` composing them?
4. Does `zucrypt` Stage 15's OAEP take SHA-256 for both the label hash
   and MGF1, as `RSA-OAEP-256` needs? Its roadmap says "OAEP" only.
5. Is a thin `jwt_*` compatibility layer for `jose` users worth its
   collision with `jose` and `httr2` exports?

## 14. Acceptance criteria

- Every RFC 7520 example whose algorithms are in scope verifies or
  decrypts, and `zujose` reproduces it byte for byte from the same CEK,
  IV and keys.
- Tokens interoperate with `jose` for every algorithm both support.
- Every RFC 8725 attack test fails closed with the documented class.
- `zujose_info()` lists exactly the algorithms the installed `zucrypt`
  supports, and the release leg skips no vector.
- The package has no `src/` and no system requirement beyond those of
  `zucrypt`, `zuutf` and `zujson`.
- R CMD check passes on the r-actions matrix offline, at the `full` tier
  on the release commit.

## 15. Sources and verification

Repository and CRAN facts checked on 1 November 2026; RFCs cited as
references:

- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) JWS,
  [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516) JWE,
  [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) JWK,
  [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) JWA,
  [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) JWT.
- [RFC 7520](https://www.rfc-editor.org/rfc/rfc7520), the JOSE cookbook;
  [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) thumbprints;
  [RFC 7797](https://www.rfc-editor.org/rfc/rfc7797) unencoded payloads;
  [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) OKP keys;
  [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) JWT best practices;
  [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394) AES key wrap.
- [`zucrypt` design](https://github.com/pedrobtz/zucrypt/blob/main/.agents/design.md)
  §6–§7.1 and
  [roadmap](https://github.com/pedrobtz/zucrypt/blob/main/.agents/roadmap.md)
  Part A, Stages 13–16; `NAMESPACE` and DESCRIPTION (0.1.0.9000) on
  `main`; open issues #9, #10, #12 and #77; crandb: 0.1.0, 2026-10-23.
- [`zuutf` design](https://github.com/pedrobtz/zuutf/blob/main/.agents/design.md)
  §5–§6; `NAMESPACE`; stage issues #1–#10; crandb `not_found`.
- `pedrobtz/zujson` `NAMESPACE` and `R/parse.R`; crandb: 0.1.0,
  2026-10-02.
- [`jose` on CRAN](https://CRAN.R-project.org/package=jose), 2.0.0, and
  its [sources](https://github.com/r-lib/jose); crandb reverse
  dependencies; `httr2`'s `NAMESPACE` on GitHub.
- [RFC 0024 pointer](https://github.com/pedrobtz/packages/blob/main/rfcs/started/0024-zuutf-unicode-transcoding.md).

Not verified for this draft: the RFC section numbers cited for individual
vectors were taken from memory of the documents' structure and are
re-checked in Stage 1; whether `zucrypt`'s point validation covers
ECDH-ES ephemeral keys; and the cost of RFC 3394 composed in R.
