# zujose 0.0.0.9000

* `jwk_public()`, and so `jwk_json()` without `private`, maps a private
  key's `key_ops` to its public half's: `sign` to `verify`, `decrypt` to
  `encrypt` and `unwrapKey` to `wrapKey`. The public half of a signing key
  could not verify. With no public operation left, `key_ops` is dropped
  (#133).

* `jwk_generate("oct")` accepts every `oct` algorithm `jwk_oct()` does: a
  `PBES2-*` password (256 bits by default), and a `dir` key named by its
  content encryption, such as `alg = "A128GCM"`, made at that algorithm's
  exact size (#132).

* A JWK's `key_ops` must be an array of strings; a JSON object is a key
  error. A present empty array permits no operation, and stays empty when
  written and read back, where before it meant no restriction. A list
  built in R may give `key_ops` as a character vector (#121).

* `as_jwk()` refuses an RSA JWK with `oth`, private or public: zujose has
  no multi-prime keys (#125).

* `as_jwk()` refuses a key whose members are not in their one canonical
  form: an RSA member with a leading zero octet, or an EC or X25519 `x`,
  `y` or `d` that is not exactly the curve's length. Such a key had a
  different thumbprint from the same key written canonically. An ECDH-ES
  `epk` is held to the same rule (#94).

* `as_jwk()` refuses a private X25519 JWK whose `x` is not the public key
  of its `d` (#124).

* Printing `jose_limits()` no longer warns in a session whose `OutDec` is
  a comma (#137).

* The default `token` limit of `jose_limits()` is 2 MiB, up from 1 MiB, so
  a token whose payload is at the default 1 MiB `payload` limit can be
  read. `token` bounds the encoded form, about 4/3 of the payload.
  Encoders do not check the limits (#134).

* `jws_verify()` counts `limits$keys` across all of a general JWS's
  signatures, not per signature, as `jwe_decrypt()` does. It checks every
  signature's algorithm and keys before verifying any (#92).

* The `header` and `payload` limits of `jose_limits()` are exact in bytes
  for Base64url parts. Before, a limit of `n` let up to two more bytes
  through in a compact or JSON JWS and in a JWE ciphertext (#91).

* `jws_sign()` refuses `b64` and `crit` in `header` or `unprotected`; the
  `b64` argument sets them. A caller's `b64: false` header with an encoded
  payload gave a token that verified as the wrong bytes (#72).

* `jwe_decrypt()` counts `limits$keys` across all of a token's recipients,
  not per recipient, so a JWE with many PBES2 or RSA recipients cannot
  multiply the key-derivation work (#37).

* `jws_verify()` and `jwt_decode()` skip a key in a set that is too weak
  for the token's algorithm, such as a legacy 1024-bit RSA key in a
  provider's JWKS, instead of failing on it. A set with only weak keys is
  still a `zujose_key_error` (#39).

* Argument errors, such as a wrong type, an out-of-range limit or
  `format = "compact"` with several recipients, now raise
  `zujose_argument_error`, a `zujose_error`, instead of a plain error (#40).

* `jwt_decode()` refuses an encrypted-only JWT whose key management is
  public-key (`RSA-OAEP*`, `RSA1_5`, `ECDH-ES*`), because anyone holding the
  recipient's public key could have made it. Its claims must come inside a
  signed JWT (`cty: "JWT"`). Encrypted-only JWTs with symmetric key
  management are still accepted (#34).

* Functions are named after the object they work on: `jwt_encode()`,
  `jwt_decode()` and `jwt_decoder()`; `jws_sign()`, `jws_signer()` and
  `jws_verify()`; `jwe_encrypt()`, `jwe_recipient()`, `jwe_decrypt()` and
  `jwe_decryption()`; `jwk_oct()`, `jwk_generate()`, `as_jwk()`,
  `jwk_set()`, `as_jwk_set()`, `jwk_public()`, `jwk_json()`, `jwk_pem()`,
  `jwk_with_kid()` and `jwk_thumbprint()`. They replace the `jose_` names
  of the development version; `jose_peek()` and `jose_limits()` keep
  theirs. Classes follow: `jwk`, `jwk_set`, `jws_verified`,
  `jwe_decrypted`, `jwt_claims`.

* Documentation: a README, and three articles on the package website: Get
  started, migrating from `jose`, and verifying tokens against a provider's
  JWKS with a caching resolver. The key help pages explain how secrets are
  held in R memory.

* `jwk_generate("oct")` accepts 128-bit keys when no `alg` is given,
  or for `dir`, as documented; it required 256 bits (#30).

* The package, developed as `zujwt`, is renamed `zujose`, the name of its
  design: conditions are `zujose_*` and `zujwt_info()` is `zujose_info()`.

* Condition classes for every error the package will raise, all
  inheriting from `zujose_error` (`?zujose_error`).

* `jose_peek()` reads a JWS or JWE in the compact, flattened or general
  JSON serialization, without verifying it, and returns every part
  decoded: its headers; for a JWS, its payload, claims, signatures and
  signing inputs; for a JWE, its encrypted keys, IV, ciphertext, tag and
  AAD.

* `jose_limits()` sets the resource limits every token is checked against
  before anything is decoded.

* Keys: `jwk_oct()` makes a symmetric key, `as_jwk()` reads a
  JWK, `jwk_json()` writes one, `jwk_public()` strips private members,
  and `jwk_thumbprint()` computes RFC 7638 thumbprints and RFC 9278
  thumbprint URIs. `jwk_with_kid()` sets `kid`, by default to the
  thumbprint. `RSA`, `EC` and `OKP` keys are read and kept but cannot be
  used yet.

* Key sets: `jwk_set()` and `as_jwk_set()`, with `[[` selecting by
  `kid`. Malformed entries in a JWK Set are ignored, as RFC 7517 asks.

* `jws_sign()` and `jws_verify()` sign and verify JWS with `HS256`,
  `HS384` and `HS512`, in all three serializations, with several signers
  through `jws_signer()`, detached payloads, and RFC 7797 unencoded
  payloads. `jws_verify()` needs `algorithms`, has no way to accept
  `none`, and refuses a key that does not fit the token's algorithm.

* `zujose_info()` lists every JOSE algorithm and whether this installation
  can use it.

* `jwt_encode()` and `jwt_decode()` sign and check JWTs.
  Decoding checks `exp`, `nbf`, `iat`, `max_age`, `iss`, `sub`, `aud`,
  `typ`, required claims, per-claim expectations and a `validate` hook in
  one call; `exp` is required by default. Each failure has its own
  condition class under `zujose_claim_error`. `jwt_decoder()` fixes a
  policy once and returns a checking function.

* `jwe_decrypt()` decrypts JWE with `dir`, `A128KW`, `A192KW` and `A256KW`
  key management and `A128CBC-HS256`, `A192CBC-HS384` and `A256CBC-HS512`
  content encryption, in all three serializations and for several
  recipients. Every decryption failure raises one class with one message.
  Compressed (`zip`) tokens are refused.

* `jwe_encrypt()` encrypts to one recipient, or to several through
  `jwe_recipient()`, with the same algorithms. Every message gets a fresh
  content encryption key and IV from the operating system's random source,
  which cannot be supplied by the caller.

* JWE gains `A128GCM`, `A192GCM` and `A256GCM` content encryption, and
  `A128GCMKW`, `A192GCMKW`, `A256GCMKW` and the three `PBES2-*` key
  management algorithms, over zucrypt's AES-GCM and PBKDF2. A PBES2 token
  whose `p2c` exceeds `jose_limits()$p2c`, or whose `p2s` is shorter than 8
  bytes, is refused before any key is derived. A `dir` key whose `alg` names
  the content encryption, as in RFC 7520 section 5.6, is accepted.

* RSA: `RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512` signatures,
  and `RSA-OAEP` and `RSA-OAEP-256` key management. `RSA1_5` decrypts only
  when `algorithms` names it, never encrypts, and fails like a wrong key
  when its padding is bad. RSA keys are read from JWKs (with all CRT
  parameters for a private key) and from PEM, written with the new
  `jwk_pem()`, generated with `jwk_generate("RSA")`, and must be at
  least 2048 bits to be used.

* Elliptic curves: `ES256`, `ES384` and `ES512` signatures (raw `r || s`),
  and `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW` and `ECDH-ES+A256KW`
  key agreement on P-256, P-384, P-521 and X25519, with the Concat KDF of
  RFC 7518. An ephemeral key that is malformed or off its curve is a parse
  error, and one on another curve than the key a key error, before any
  key agreement. EC and X25519 keys are read from JWKs and PEM, written by
  `jwk_pem()` and generated by `jwk_generate("EC")` and `("OKP")`.
  Ed25519 keys are read and kept but cannot be used.

* `jwk_generate()` makes a random `oct` key, sized for its `alg`.
  `RSA`, `EC` and `OKP` generation names the zucrypt version it needs.

* `jwt_encode(jti = TRUE)` adds a random 128-bit `jti`.

* zujose now needs the development version of zucrypt, for
  `crypt_rand_bytes()`, `crypt_aes_gcm_encrypt()` and `crypt_pbkdf2()`.
  `zujose_info()` reports an algorithm available when the installed zucrypt
  exports what it needs, so a development zucrypt counts.

* `jwt_decode()` accepts a JWT sent as a JWE only with
  `decrypt = jwe_decryption(...)`.
