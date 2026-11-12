# Changelog

## zujose 0.0.0.9000

- A header, JWS JSON token or claims set nested more than about 800
  levels deep, which zujson parses up to 1000, no longer exhausts the C
  stack: the check for repeated member names and the `claims` comparison
  walk the value level by level instead of recursing
  ([\#141](https://github.com/pedrobtz/zujose/issues/141)).

- [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  refuses a JWT with an unencoded payload (`b64: false`), outer or
  nested, with `zujose_policy_error` before any key is tried (RFC 7797
  section 7). It returned the claims
  ([\#126](https://github.com/pedrobtz/zujose/issues/126)).

- [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  refuses an `exp`, `nbf` or `iat` beyond any time `POSIXct` can
  represent, such as `1e308`, with `zujose_parse_error`. It returned the
  claim as an `NA` time.
  [`jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jwt_encode.md)
  refuses such a time, from `claims`, `expires_in` or `not_before`, with
  `zujose_argument_error`, so it no longer writes a token
  [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  refuses ([\#127](https://github.com/pedrobtz/zujose/issues/127)).

- [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  and
  [`jwt_decoder()`](https://pedrobtz.github.io/zujose/reference/jwt_decoder.md)
  refuse repeated, `NA` or empty names in `claims` with
  `zujose_argument_error`. Only the first of two expectations for one
  claim was checked
  ([\#118](https://github.com/pedrobtz/zujose/issues/118)).

- Expectations in `jwt_decode(claims = )` compare JSON values, not JSON
  text: object members may come in any order. `NA` and non-finite
  numbers are refused rather than matching `null`, and `NULL` expects
  `null`. `exp`, `nbf` and `iat` are compared, and passed to a function,
  as the `POSIXct` times
  [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  returns.
  [`?jwt_decode`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  says how vectors and arrays match
  ([\#128](https://github.com/pedrobtz/zujose/issues/128)).

- [`jose_peek()`](https://pedrobtz.github.io/zujose/reference/jose_peek.md)
  gives `NULL` for `payload` and `signing_input` on a compact detached
  JWS, as it does for a flattened one. It gave `raw(0)` and the header
  followed by `"."`
  ([\#131](https://github.com/pedrobtz/zujose/issues/131)).

- [`?jwe_encrypt`](https://pedrobtz.github.io/zujose/reference/jwe_encrypt.md)
  documents that other JOSE implementations cap PBES2 `p2c` when they
  decrypt (jwcrypto at 16 384, JavaScript’s `jose` at 10 000), so a
  token for them needs `header = list(p2c = 10000)` or less. The default
  stays 600 000
  ([\#140](https://github.com/pedrobtz/zujose/issues/140)).

- [`jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jwt_encode.md)
  documents `key` as one `jwk`, and refuses
  [`jws_signer()`](https://pedrobtz.github.io/zujose/reference/jws_signer.md)s
  with a clear `zujose_argument_error`: a JWT is compact and has one
  signature. It inherited a list-of-signers `key` from
  [`jws_sign()`](https://pedrobtz.github.io/zujose/reference/jws_sign.md)
  that its own default header made it refuse
  ([\#130](https://github.com/pedrobtz/zujose/issues/130)).

- Errors that escaped as base R, zucrypt or zujson conditions are now
  `zujose_error`s: an `enc` that is not one string in
  [`jwe_encrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_encrypt.md),
  a NUL byte in an unencoded (`b64 = FALSE`) payload, an RSA `size` that
  is not a multiple of 8 in
  [`jwk_generate()`](https://pedrobtz.github.io/zujose/reference/jwk_generate.md)
  (now documented), a bad index in `[[` on a `jwk_set`, and a PBES2
  `p2c` beyond 2^32 - 1, which is a parse error even under
  `jose_limits(p2c = Inf)`
  ([\#123](https://github.com/pedrobtz/zujose/issues/123)).

- Names on R arguments no longer change the JSON zujose writes or the
  values it compares. A named `expires_in`, `not_before`, `exp`, `nbf`,
  `iat`, `p2c`, `alg`, `enc`, `kid`, `typ` or registered claim was
  written as an object, a named list of
  [`jws_signer()`](https://pedrobtz.github.io/zujose/reference/jws_signer.md)s
  wrote `signatures` as an object, and a named `issuer` or `subject` in
  [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  never matched
  ([\#120](https://github.com/pedrobtz/zujose/issues/120)).

- [`jwe_encrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_encrypt.md)
  and
  [`jwe_recipient()`](https://pedrobtz.github.io/zujose/reference/jwe_recipient.md)
  refuse `zip` in every header with `zujose_argument_error`. In
  `unprotected` or a recipient’s header it was written over content that
  was never compressed
  ([\#117](https://github.com/pedrobtz/zujose/issues/117)).

- [`jwe_encrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_encrypt.md)
  refuses a
  [`jwe_recipient()`](https://pedrobtz.github.io/zujose/reference/jwe_recipient.md)
  header `alg` that disagrees with the recipient’s algorithm, in every
  format, as
  [`jws_sign()`](https://pedrobtz.github.io/zujose/reference/jws_sign.md)
  does. It was silently replaced in the general serialization
  ([\#129](https://github.com/pedrobtz/zujose/issues/129)).

- [`jws_sign()`](https://pedrobtz.github.io/zujose/reference/jws_sign.md),
  [`jws_signer()`](https://pedrobtz.github.io/zujose/reference/jws_signer.md),
  [`jwe_encrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_encrypt.md),
  [`jwe_recipient()`](https://pedrobtz.github.io/zujose/reference/jwe_recipient.md)
  and
  [`jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jwt_encode.md)
  refuse, with `zujose_argument_error`, a header or claims set with a
  repeated, `NA` or empty name at any depth, a member given in more than
  one header, a data frame or unnamed list as the claims set, and a
  value JSON cannot represent, such as a raw or complex vector. A
  repeated header member was dropped and a nested one written, giving
  tokens zujose’s own decoder refuses
  ([\#119](https://github.com/pedrobtz/zujose/issues/119),
  [\#123](https://github.com/pedrobtz/zujose/issues/123)).

- Header members and key members are read by their exact names. A
  `p2count` header member no longer sets the PBES2 iteration count, and
  a `kidnap` header no longer prints as the key’s `kid`
  ([\#122](https://github.com/pedrobtz/zujose/issues/122)).

- Printing a key of an unknown `kty` says “unknown key type” instead of
  “needs zucrypt (\>= NA)”
  ([\#136](https://github.com/pedrobtz/zujose/issues/136)).

- `[` on a `jwk_set` refuses an NA or out-of-range index with
  `zujose_argument_error`, instead of making a set that holds `NULL` and
  cannot be printed
  ([\#135](https://github.com/pedrobtz/zujose/issues/135)).

- [`jwk_public()`](https://pedrobtz.github.io/zujose/reference/jwk_public.md),
  and so
  [`jwk_json()`](https://pedrobtz.github.io/zujose/reference/jwk_json.md)
  without `private`, maps a private key’s `key_ops` to its public
  half’s: `sign` to `verify`, `decrypt` to `encrypt` and `unwrapKey` to
  `wrapKey`. The public half of a signing key could not verify. With no
  public operation left, `key_ops` is dropped
  ([\#133](https://github.com/pedrobtz/zujose/issues/133)).

- `jwk_generate("oct")` accepts every `oct` algorithm
  [`jwk_oct()`](https://pedrobtz.github.io/zujose/reference/jwk_oct.md)
  does: a `PBES2-*` password (256 bits by default), and a `dir` key
  named by its content encryption, such as `alg = "A128GCM"`, made at
  that algorithm’s exact size
  ([\#132](https://github.com/pedrobtz/zujose/issues/132)).

- A JWK’s `key_ops` must be an array of strings; a JSON object is a key
  error. A present empty array permits no operation, and stays empty
  when written and read back, where before it meant no restriction. A
  list built in R may give `key_ops` as a character vector
  ([\#121](https://github.com/pedrobtz/zujose/issues/121)).

- [`as_jwk()`](https://pedrobtz.github.io/zujose/reference/as_jwk.md)
  refuses an RSA JWK with `oth`, private or public: zujose has no
  multi-prime keys
  ([\#125](https://github.com/pedrobtz/zujose/issues/125)).

- [`as_jwk()`](https://pedrobtz.github.io/zujose/reference/as_jwk.md)
  refuses a key whose members are not in their one canonical form: an
  RSA member with a leading zero octet, or an EC or X25519 `x`, `y` or
  `d` that is not exactly the curve’s length. Such a key had a different
  thumbprint from the same key written canonically. An ECDH-ES `epk` is
  held to the same rule
  ([\#94](https://github.com/pedrobtz/zujose/issues/94)).

- [`as_jwk()`](https://pedrobtz.github.io/zujose/reference/as_jwk.md)
  refuses a private X25519 JWK whose `x` is not the public key of its
  `d` ([\#124](https://github.com/pedrobtz/zujose/issues/124)).

- Printing
  [`jose_limits()`](https://pedrobtz.github.io/zujose/reference/jose_limits.md)
  no longer warns in a session whose `OutDec` is a comma
  ([\#137](https://github.com/pedrobtz/zujose/issues/137)).

- The default `token` limit of
  [`jose_limits()`](https://pedrobtz.github.io/zujose/reference/jose_limits.md)
  is 2 MiB, up from 1 MiB, so a token whose payload is at the default 1
  MiB `payload` limit can be read. `token` bounds the encoded form,
  about 4/3 of the payload. Encoders do not check the limits
  ([\#134](https://github.com/pedrobtz/zujose/issues/134)).

- [`jws_verify()`](https://pedrobtz.github.io/zujose/reference/jws_verify.md)
  counts `limits$keys` across all of a general JWS’s signatures, not per
  signature, as
  [`jwe_decrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_decrypt.md)
  does. It checks every signature’s algorithm and keys before verifying
  any ([\#92](https://github.com/pedrobtz/zujose/issues/92)).

- The `header` and `payload` limits of
  [`jose_limits()`](https://pedrobtz.github.io/zujose/reference/jose_limits.md)
  are exact in bytes for Base64url parts. Before, a limit of `n` let up
  to two more bytes through in a compact or JSON JWS and in a JWE
  ciphertext ([\#91](https://github.com/pedrobtz/zujose/issues/91)).

- [`jws_sign()`](https://pedrobtz.github.io/zujose/reference/jws_sign.md)
  refuses `b64` and `crit` in `header` or `unprotected`; the `b64`
  argument sets them. A caller’s `b64: false` header with an encoded
  payload gave a token that verified as the wrong bytes
  ([\#72](https://github.com/pedrobtz/zujose/issues/72)).

- [`jwe_decrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_decrypt.md)
  counts `limits$keys` across all of a token’s recipients, not per
  recipient, so a JWE with many PBES2 or RSA recipients cannot multiply
  the key-derivation work
  ([\#37](https://github.com/pedrobtz/zujose/issues/37)).

- [`jws_verify()`](https://pedrobtz.github.io/zujose/reference/jws_verify.md)
  and
  [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  skip a key in a set that is too weak for the token’s algorithm, such
  as a legacy 1024-bit RSA key in a provider’s JWKS, instead of failing
  on it. A set with only weak keys is still a `zujose_key_error`
  ([\#39](https://github.com/pedrobtz/zujose/issues/39)).

- Argument errors, such as a wrong type, an out-of-range limit or
  `format = "compact"` with several recipients, now raise
  `zujose_argument_error`, a `zujose_error`, instead of a plain error
  ([\#40](https://github.com/pedrobtz/zujose/issues/40)).

- [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  refuses an encrypted-only JWT whose key management is public-key
  (`RSA-OAEP*`, `RSA1_5`, `ECDH-ES*`), because anyone holding the
  recipient’s public key could have made it. Its claims must come inside
  a signed JWT (`cty: "JWT"`). Encrypted-only JWTs with symmetric key
  management are still accepted
  ([\#34](https://github.com/pedrobtz/zujose/issues/34)).

- Functions are named after the object they work on:
  [`jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jwt_encode.md),
  [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  and
  [`jwt_decoder()`](https://pedrobtz.github.io/zujose/reference/jwt_decoder.md);
  [`jws_sign()`](https://pedrobtz.github.io/zujose/reference/jws_sign.md),
  [`jws_signer()`](https://pedrobtz.github.io/zujose/reference/jws_signer.md)
  and
  [`jws_verify()`](https://pedrobtz.github.io/zujose/reference/jws_verify.md);
  [`jwe_encrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_encrypt.md),
  [`jwe_recipient()`](https://pedrobtz.github.io/zujose/reference/jwe_recipient.md),
  [`jwe_decrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_decrypt.md)
  and
  [`jwe_decryption()`](https://pedrobtz.github.io/zujose/reference/jwe_decryption.md);
  [`jwk_oct()`](https://pedrobtz.github.io/zujose/reference/jwk_oct.md),
  [`jwk_generate()`](https://pedrobtz.github.io/zujose/reference/jwk_generate.md),
  [`as_jwk()`](https://pedrobtz.github.io/zujose/reference/as_jwk.md),
  [`jwk_set()`](https://pedrobtz.github.io/zujose/reference/jwk_set.md),
  [`as_jwk_set()`](https://pedrobtz.github.io/zujose/reference/jwk_set.md),
  [`jwk_public()`](https://pedrobtz.github.io/zujose/reference/jwk_public.md),
  [`jwk_json()`](https://pedrobtz.github.io/zujose/reference/jwk_json.md),
  [`jwk_pem()`](https://pedrobtz.github.io/zujose/reference/jwk_pem.md),
  [`jwk_with_kid()`](https://pedrobtz.github.io/zujose/reference/jwk_with_kid.md)
  and
  [`jwk_thumbprint()`](https://pedrobtz.github.io/zujose/reference/jwk_thumbprint.md).
  They replace the `jose_` names of the development version;
  [`jose_peek()`](https://pedrobtz.github.io/zujose/reference/jose_peek.md)
  and
  [`jose_limits()`](https://pedrobtz.github.io/zujose/reference/jose_limits.md)
  keep theirs. Classes follow: `jwk`, `jwk_set`, `jws_verified`,
  `jwe_decrypted`, `jwt_claims`.

- Documentation: a README, and three articles on the package website:
  Get started, migrating from `jose`, and verifying tokens against a
  provider’s JWKS with a caching resolver. The key help pages explain
  how secrets are held in R memory.

- `jwk_generate("oct")` accepts 128-bit keys when no `alg` is given, or
  for `dir`, as documented; it required 256 bits
  ([\#30](https://github.com/pedrobtz/zujose/issues/30)).

- The package, developed as `zujwt`, is renamed `zujose`, the name of
  its design: conditions are `zujose_*` and `zujwt_info()` is
  [`zujose_info()`](https://pedrobtz.github.io/zujose/reference/zujose_info.md).

- Condition classes for every error the package will raise, all
  inheriting from `zujose_error`
  ([`?zujose_error`](https://pedrobtz.github.io/zujose/reference/zujose_error.md)).

- [`jose_peek()`](https://pedrobtz.github.io/zujose/reference/jose_peek.md)
  reads a JWS or JWE in the compact, flattened or general JSON
  serialization, without verifying it, and returns every part decoded:
  its headers; for a JWS, its payload, claims, signatures and signing
  inputs; for a JWE, its encrypted keys, IV, ciphertext, tag and AAD.

- [`jose_limits()`](https://pedrobtz.github.io/zujose/reference/jose_limits.md)
  sets the resource limits every token is checked against before
  anything is decoded.

- Keys:
  [`jwk_oct()`](https://pedrobtz.github.io/zujose/reference/jwk_oct.md)
  makes a symmetric key,
  [`as_jwk()`](https://pedrobtz.github.io/zujose/reference/as_jwk.md)
  reads a JWK,
  [`jwk_json()`](https://pedrobtz.github.io/zujose/reference/jwk_json.md)
  writes one,
  [`jwk_public()`](https://pedrobtz.github.io/zujose/reference/jwk_public.md)
  strips private members, and
  [`jwk_thumbprint()`](https://pedrobtz.github.io/zujose/reference/jwk_thumbprint.md)
  computes RFC 7638 thumbprints and RFC 9278 thumbprint URIs.
  [`jwk_with_kid()`](https://pedrobtz.github.io/zujose/reference/jwk_with_kid.md)
  sets `kid`, by default to the thumbprint. `RSA`, `EC` and `OKP` keys
  are read and kept but cannot be used yet.

- Key sets:
  [`jwk_set()`](https://pedrobtz.github.io/zujose/reference/jwk_set.md)
  and
  [`as_jwk_set()`](https://pedrobtz.github.io/zujose/reference/jwk_set.md),
  with `[[` selecting by `kid`. Malformed entries in a JWK Set are
  ignored, as RFC 7517 asks.

- [`jws_sign()`](https://pedrobtz.github.io/zujose/reference/jws_sign.md)
  and
  [`jws_verify()`](https://pedrobtz.github.io/zujose/reference/jws_verify.md)
  sign and verify JWS with `HS256`, `HS384` and `HS512`, in all three
  serializations, with several signers through
  [`jws_signer()`](https://pedrobtz.github.io/zujose/reference/jws_signer.md),
  detached payloads, and RFC 7797 unencoded payloads.
  [`jws_verify()`](https://pedrobtz.github.io/zujose/reference/jws_verify.md)
  needs `algorithms`, has no way to accept `none`, and refuses a key
  that does not fit the token’s algorithm.

- [`zujose_info()`](https://pedrobtz.github.io/zujose/reference/zujose_info.md)
  lists every JOSE algorithm and whether this installation can use it.

- [`jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jwt_encode.md)
  and
  [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  sign and check JWTs. Decoding checks `exp`, `nbf`, `iat`, `max_age`,
  `iss`, `sub`, `aud`, `typ`, required claims, per-claim expectations
  and a `validate` hook in one call; `exp` is required by default. Each
  failure has its own condition class under `zujose_claim_error`.
  [`jwt_decoder()`](https://pedrobtz.github.io/zujose/reference/jwt_decoder.md)
  fixes a policy once and returns a checking function.

- [`jwe_decrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_decrypt.md)
  decrypts JWE with `dir`, `A128KW`, `A192KW` and `A256KW` key
  management and `A128CBC-HS256`, `A192CBC-HS384` and `A256CBC-HS512`
  content encryption, in all three serializations and for several
  recipients. Every decryption failure raises one class with one
  message. Compressed (`zip`) tokens are refused.

- [`jwe_encrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_encrypt.md)
  encrypts to one recipient, or to several through
  [`jwe_recipient()`](https://pedrobtz.github.io/zujose/reference/jwe_recipient.md),
  with the same algorithms. Every message gets a fresh content
  encryption key and IV from the operating system’s random source, which
  cannot be supplied by the caller.

- JWE gains `A128GCM`, `A192GCM` and `A256GCM` content encryption, and
  `A128GCMKW`, `A192GCMKW`, `A256GCMKW` and the three `PBES2-*` key
  management algorithms, over zucrypt’s AES-GCM and PBKDF2. A PBES2
  token whose `p2c` exceeds `jose_limits()$p2c`, or whose `p2s` is
  shorter than 8 bytes, is refused before any key is derived. A `dir`
  key whose `alg` names the content encryption, as in RFC 7520 section
  5.6, is accepted.

- RSA: `RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512`
  signatures, and `RSA-OAEP` and `RSA-OAEP-256` key management. `RSA1_5`
  decrypts only when `algorithms` names it, never encrypts, and fails
  like a wrong key when its padding is bad. RSA keys are read from JWKs
  (with all CRT parameters for a private key) and from PEM, written with
  the new
  [`jwk_pem()`](https://pedrobtz.github.io/zujose/reference/jwk_pem.md),
  generated with `jwk_generate("RSA")`, and must be at least 2048 bits
  to be used.

- Elliptic curves: `ES256`, `ES384` and `ES512` signatures (raw
  `r || s`), and `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW` and
  `ECDH-ES+A256KW` key agreement on P-256, P-384, P-521 and X25519, with
  the Concat KDF of RFC 7518. An ephemeral key that is malformed or off
  its curve is a parse error, and one on another curve than the key a
  key error, before any key agreement. EC and X25519 keys are read from
  JWKs and PEM, written by
  [`jwk_pem()`](https://pedrobtz.github.io/zujose/reference/jwk_pem.md)
  and generated by `jwk_generate("EC")` and `("OKP")`. Ed25519 keys are
  read and kept but cannot be used.

- [`jwk_generate()`](https://pedrobtz.github.io/zujose/reference/jwk_generate.md)
  makes a random `oct` key, sized for its `alg`. `RSA`, `EC` and `OKP`
  generation names the zucrypt version it needs.

- `jwt_encode(jti = TRUE)` adds a random 128-bit `jti`.

- zujose now needs the development version of zucrypt, for
  `crypt_rand_bytes()`, `crypt_aes_gcm_encrypt()` and `crypt_pbkdf2()`.
  [`zujose_info()`](https://pedrobtz.github.io/zujose/reference/zujose_info.md)
  reports an algorithm available when the installed zucrypt exports what
  it needs, so a development zucrypt counts.

- [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  accepts a JWT sent as a JWE only with `decrypt = jwe_decryption(...)`.
