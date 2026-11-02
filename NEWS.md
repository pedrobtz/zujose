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
