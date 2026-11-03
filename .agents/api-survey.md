# JOSE APIs in Python and Go: survey for zujose §7

Surveyed 2026-11-02 to shape [design.md](design.md) §7. Signatures marked
[doc] were checked against current documentation. The rest come from
knowledge of the sources and should be spot-checked before they are quoted
elsewhere.

Sources:

- PyJWT: <https://pyjwt.readthedocs.io/en/stable/api.html>
- joserfc: <https://jose.authlib.org/en/guide/jwt/> and the jws, jwe and
  jwk guides
- jwcrypto: <https://jwcrypto.readthedocs.io/en/latest/jwt.html>
- python-jose: <https://github.com/mpdavis/python-jose>,
  <https://github.com/advisories/GHSA-6c5p-j8vq-pqhj>
- go-jose: <https://pkg.go.dev/github.com/go-jose/go-jose/v4> and `/v4/jwt`
- golang-jwt: <https://pkg.go.dev/github.com/golang-jwt/jwt/v5>
- jwx: <https://pkg.go.dev/github.com/lestrrat-go/jwx/v3/jwt> and
  `/v3/jws`; v4 announcement
  <https://github.com/lestrrat-go/jwx/discussions/2040>
- joserfc advisories:
  <https://github.com/authlib/joserfc/security/advisories/GHSA-frfh-8v73-gjg4>,
  <https://osv.dev/vulnerability/CVE-2026-75509>

jwx v4 shipped in April 2026 and needs `encoding/json/v2`; v3 is still
maintained. go-jose is at v4.1.

## Per library

### PyJWT (JWS and JWT, no JWE) [doc]

- `encode(payload, key, algorithm, headers)`.
- `decode(jwt, key, algorithms, options, audience, issuer, subject,
  leeway, detached_payload)`.
- `get_unverified_header()`.
- Keys: `PyJWK`, `PyJWKSet` and `PyJWKClient(uri)`.
- Options are a dict of `verify_*` booleans plus `require=[...]`.
- `algorithms` has been mandatory since 2.0. Leeway defaults to 0. Claims
  are checked only when present.
- Exceptions: `PyJWTError` → `InvalidTokenError` →
  `ExpiredSignatureError`, `InvalidAudienceError`,
  `MissingRequiredClaimError`, …
- CVEs:
  - CVE-2017-11424 and CVE-2022-29217: algorithm confusion.
  - CVE-2024-53861: partial `iss` match.

### joserfc (Authlib)

- JWS: `jws.serialize_compact/json`.
- JWE: `jwe.encrypt_compact/json`, with multiple recipients.
- JWT: `jwt.encode(header, claims, key)` and `jwt.decode(text, key)`.
- Keys: `jwk.import_key`, `generate_key`, `KeySet`, `thumbprint()`,
  `thumbprint_uri()` (RFC 9278) and `ensure_kid()` [doc].
- The key argument may be a key, a key set or a callable resolver.
- Registries carry the policy. Algorithms default to a "recommended" set.
- Claims are validated in a **separate** step, `JWTClaimsRegistry(...)
  .validate()`, using `essential`, `value` and `values`.
- Coverage is the broadest in Python, including EdDSA, ES256K, PBES2,
  ECDH-ES and DEF.
- CVEs:
  - CVE-2025-65015: token echoed in errors.
  - CVE-2026-27932: unbounded `p2c`.
  - CVE-2026-48990: `b64=false` skipped size limits.
  - CVE-2026-75509: array `iss` matched by membership.

### jwcrypto

- Object style: `JWK.generate`, `from_json`, `from_pem`,
  `thumbprint`, `JWS(payload).add_signature()` and
  `JWE(...).add_recipient()`.
- `JWT(jwt=, key=, algs=, check_claims=, expected_type=)` [doc]. In
  `check_claims`, `None` means present and a value means equal. Leeway is
  60.
- CVEs:
  - CVE-2022-3102: JWS/JWE type confusion, the reason for
    `expected_type`.
  - CVE-2023-6681: `p2c` DoS.
  - CVE-2024-28102: zip bomb.

### python-jose (avoid as a model)

- `algorithms` is optional.
- CVE-2024-33663 (algorithm confusion) and CVE-2024-33664 (JWE size
  bomb); the fix for 33663 is reported incomplete.
- Maintenance is slow. No EdDSA.

### go-jose v4

- Parsing: `ParseSignedCompact/JSON(s, algs)` and
  `ParseEncrypted*(s, keyAlgs, encs)`. **Allow-lists became mandatory in
  v4** [doc].
- Signing and encrypting: `NewSigner`, `NewMultiSigner`, `NewEncrypter`,
  with chained options.
- Verifying and decrypting: `Verify`, `VerifyMulti`, `DetachedVerify`,
  `Decrypt`.
- Keys: a `JSONWebKeySet` is selected by kid. `Thumbprint`, `Public()`.
  There is no key generation.
- JWT: `Claims.ValidateWithLeeway(Expected{Issuer, Subject, AnyAudience,
  ID, Time}, leeway)`. Default leeway is 1 minute. `typ` is not checked.
- Global limits `MaxRecipients` and `MaxSignatures` (32).
- CVEs: CVE-2024-28180 (zip bomb), CVE-2025-27144.

### golang-jwt v5 (JWT and JWS, no JWK or JWE)

- `Parse(tok, Keyfunc, ...ParserOption)` and `ParseUnverified`.
- `Keyfunc` is `func(*Token) (any, error)`.
- Functional options: `WithValidMethods`, `WithLeeway`, `WithAudience`,
  `WithIssuer`, `WithSubject`, `WithExpirationRequired`, `WithIssuedAt`,
  `WithTimeFunc` [doc].
- Custom validation: a `ClaimsValidator` interface.
- Errors are `errors.Is` sentinels.
- **`WithValidMethods` is optional**, which is the classic confusion risk.
- CVEs: CVE-2020-26160 (`aud`), CVE-2025-30204 (DoS).

### lestrrat-go/jwx v3/v4

- Packages: `jwk`, `jws`, `jwe`, `jwt`.
- Signing: `jws.Sign(payload, jws.WithKey(alg, key, ...)...)`. Repeating
  `WithKey` gives multiple signers.
- Verifying: `jws.Verify(buf, WithKey | WithKeySet(set, WithRequireKid,
  WithInferAlgorithmFromKey) | WithKeyProvider(f), WithDetachedPayload)`
  [doc].
- The algorithm is bound to the key the caller supplies.
- `jku` is honoured only through `WithVerifyAuto` with a fetcher
  allow-list.
- `jwt.Parse` validate options: `WithAcceptableSkew`, `WithClock`,
  `WithAudience`, `WithIssuer`, `WithSubject`, `WithRequiredClaim`,
  `WithClaimValue`, `WithMaxDelta`, `WithValidator` [doc].
- `jwk.Cache` auto-refreshes a JWKS.
- CVEs: CVE-2023-49290 (`p2c`), CVE-2024-28122 (zip bomb).

## Feature matrix

✓ yes, – no, ~ partial or opt-in.

| Feature | PyJWT | joserfc | jwcrypto | py-jose | go-jose | golang-jwt | jwx |
| --- | --- | --- | --- | --- | --- | --- | --- |
| JWE | – | ✓ | ✓ | ✓ | ✓ | – | ✓ |
| Multi-signer or multi-recipient | – | ✓ | ✓ | – | ✓ | – | ✓ |
| JWS JSON serializations | – | ✓ | ✓ | – | ✓ | – | ✓ |
| Detached or `b64=false` | ✓ | ✓ | ~ | – | ✓ | – | ✓ |
| Allow-list required | ✓ | default | default | – | ✓ | – | key-bound |
| Key resolver | – | ✓ | – | – | – | ✓ | ✓ |
| JWKS by kid | ✓ | ✓ | ✓ | ~ | ✓ | ~ | ✓ |
| JWKS fetch and cache | ✓ | – | – | – | – | – | ✓ |
| Key generation | – | ✓ | ✓ | – | – | – | – |
| RFC 7638 thumbprint | – | ✓ | ✓ | – | ✓ | – | ✓ |
| Custom claim validators | – | ✓ | – | – | – | ✓ | ✓ |
| `typ` check | – | ~ | ✓ | – | – | – | – |
| EdDSA | ✓ | ✓ | ✓ | – | ✓ | ✓ | ✓ |
| Default leeway (s) | 0 | 0 | 60 | 0 | 60 | 0 | 0 |

## Patterns

Copy:

1. A mandatory allow-list on every verify and decrypt, with encryptions
   kept separate (go-jose v4, PyJWT 2).
2. The algorithm bound to the key, not only to the header (jwx).
3. A `key` that may be a key, a key set or a function (joserfc,
   golang-jwt, jwx).
4. Declarative per-claim expectations plus a validator hook (joserfc,
   jwx).
5. Typed errors matched by class, with leaves for expired, audience and
   issuer (PyJWT).
6. Resource caps checked before work, including on the `b64=false` path
   (go-jose; joserfc missed that path).
7. Thumbprint-derived kid and public-key extraction (joserfc, go-jose).
8. Single-value `iss` and `sub` matching (PyJWT and joserfc CVEs).

Avoid:

1. An optional allow-list (golang-jwt, python-jose).
2. Decoding that skips claim checks by default (joserfc's two steps).
3. `verify_*` boolean options (PyJWT); use a separately named unverified
   function.
4. Echoing token material in errors (joserfc).
5. `zip` and unbounded `p2c` (zip-bomb and `p2c` CVEs in go-jose, jwx,
   jwcrypto and joserfc).
