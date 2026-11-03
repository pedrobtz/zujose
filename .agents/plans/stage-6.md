# Stage 6 — Generated keys and IVs: plan

Scratch. The roadmap's Stage 6 section is authoritative.

1. `DESCRIPTION`: `zucrypt (>= 0.1.0.9000)`, `Remotes: pedrobtz/zucrypt`.
   That is zucrypt's `main` with `crypt_rand_bytes()` (zucrypt#83).
2. JWE: the CEK and IV come from `zucrypt::crypt_rand_bytes()`. The
   `random_bytes()` stub goes. `encrypt_jwe()` keeps `cek` and `iv` for
   `encrypt_fixed()`; `jose_encrypt()` has neither (test on `formals()`).
   Test: two encryptions of one plaintext differ and both decrypt, for `dir`
   and `A*KW`, compact and JSON.
3. `jose_jwt_encode(jti = TRUE)`: 16 random bytes, Base64url, unless
   `claims` sets `jti`. Tests: 22 characters, distinct, caller's kept.
4. `jose_key_generate(kty, size, crv, alg, kid, use, key_ops)`: `oct` now;
   `RSA`, `EC`, `OKP` raise `zujwt_unsupported_error` naming 0.4.0 / 0.5.0.
   `size` in bits, a multiple of 8, at least 128. The default follows `alg`
   (HS* hash size, A*KW and A*GCMKW exact), else 256. An `alg` that is not
   an `oct` algorithm, or a size it cannot use, is `zujwt_key_error`.
5. Docs: `jose_encrypt()` and `jose_jwt_encode()` drop the "needs
   zucrypt 0.2.0" text and runnable examples; `NEWS.md`; `_pkgdown.yml`;
   roadmap dependency row and stage table; `CLAUDE.md` current state.
