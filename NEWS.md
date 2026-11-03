# zujwt 0.0.0.9000

* Condition classes for every error the package will raise, all
  inheriting from `zujwt_error` (`?zujwt_error`).

* `jose_peek()` reads a JWS or JWE in the compact, flattened or general
  JSON serialization, without verifying it, and returns its headers and,
  for a JWS, its payload and claims.

* `jose_limits()` sets the resource limits every token is checked against
  before anything is decoded.

* Keys: `jose_key_oct()` makes a symmetric key, `as_jose_key()` reads a
  JWK, `jose_jwk()` writes one, `jose_public()` strips private members,
  and `jose_thumbprint()` computes RFC 7638 thumbprints and RFC 9278
  thumbprint URIs. `jose_with_kid()` sets `kid`, by default to the
  thumbprint. `RSA`, `EC` and `OKP` keys are read and kept but cannot be
  used yet.

* Key sets: `jose_keyset()` and `as_jose_keyset()`, with `[[` selecting by
  `kid`. Malformed entries in a JWK Set are ignored, as RFC 7517 asks.

* `jose_sign()` and `jose_verify()` sign and verify JWS with `HS256`,
  `HS384` and `HS512`, in all three serializations, with several signers
  through `jose_signer()`, detached payloads, and RFC 7797 unencoded
  payloads. `jose_verify()` needs `algorithms`, has no way to accept
  `none`, and refuses a key that does not fit the token's algorithm.

* `zujwt_info()` lists every JOSE algorithm and whether this installation
  can use it.

* `jose_jwt_encode()` and `jose_jwt_decode()` sign and check JWTs.
  Decoding checks `exp`, `nbf`, `iat`, `max_age`, `iss`, `sub`, `aud`,
  `typ`, required claims, per-claim expectations and a `validate` hook in
  one call; `exp` is required by default. Each failure has its own
  condition class under `zujwt_claim_error`. `jose_jwt_decoder()` fixes a
  policy once and returns a checking function.

* `jose_decrypt()` decrypts JWE with `dir`, `A128KW`, `A192KW` and `A256KW`
  key management and `A128CBC-HS256`, `A192CBC-HS384` and `A256CBC-HS512`
  content encryption, in all three serializations and for several
  recipients. Every decryption failure raises one class with one message.
  Compressed (`zip`) tokens are refused.

* `jose_encrypt()` encrypts to one recipient, or to several through
  `jose_recipient()`, with the same algorithms. Every message gets a fresh
  content encryption key and IV from the operating system's random source,
  which cannot be supplied by the caller.

* `jose_key_generate()` makes a random `oct` key, sized for its `alg`.
  `RSA`, `EC` and `OKP` generation names the zucrypt version it needs.

* `jose_jwt_encode(jti = TRUE)` adds a random 128-bit `jti`.

* zujwt now needs the development version of zucrypt, for
  `crypt_rand_bytes()`.

* `jose_jwt_decode()` accepts a JWT sent as a JWE only with
  `decrypt = jose_decryption(...)`.
