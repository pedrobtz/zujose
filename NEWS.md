# zujose 0.0.0.9000

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
