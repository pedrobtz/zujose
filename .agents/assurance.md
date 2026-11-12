# Assurance

How this package meets `.claude/shared/assurance.md`. CI checks this
file (r-actions `assurance.yml`), so keep the headings and table
columns as they are.

- **Statuses:** a cell is a fact, `gap #<issue>` or `n/a: <reason>`.
- **Written:** 2026-11-12, from the code at b8b4be4, by `pkg-assurance`.
  Each oracle was read from the test's assertion, not from the design.
  Writing it found five bugs, filed apart from the gaps: #91 to #95.
- **Not `compiled`:** there is no `src/`. Every primitive is a zucrypt
  function, so the native checks belong to zucrypt, zuutf and zujson.
- **Not `lifecycle`:** keys, key sets and limits are plain lists. Nothing
  zujose returns holds an environment, a pointer or a finalizer, so there
  is no Objects table.
- **"jwcrypto, dev"** means `tools/jwe-oracle/`, run by
  `jwe-oracle.yaml`. That job exchanges compact JWE only, and it never
  runs at check time.

## Kinds

`untrusted-input` `spec` `emits`

## Required checks

`Where` names the workflow file under `.github/workflows/` that runs the
check. Add `(own)` when that workflow is the package's own rather than a
call to r-actions.

| Check      | Status | Where |
| ---------- | ------ | ----- |
| fuzz       | gap #96 |       |
| fuzz-reach | gap #97 |       |

## Boundaries

One row per boundary the package crosses. An oracle knows the answer:

- a conformance suite or test vectors;
- a reference implementation;
- a round trip;
- equivalent inputs compared;
- the bytes the other side received.

"No crash" is not an oracle.

<!-- markdownlint-disable MD013 -->
| Boundary                                  | Oracle                                                                                  | Carried by                                                    |
| ----------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| Base64url decode, strict and canonical    | hand-computed values; nine non-canonical forms refused                                  | tests/testthat/test-b64url.R                                  |
| Base64url encode                          | round trip for lengths 0 to 64; RFC tokens reproduced byte for byte                     | tests/testthat/test-b64url.R, test-jws.R                      |
| JWS compact parse                         | RFC 7520 §4.1 parts; every RFC 7520 figure's type and serialization                     | tests/testthat/test-codec.R                                   |
| JWS JSON parse, general and flattened     | RFC 7520 §4 verified; the three serializations of one token parse alike                 | tests/testthat/test-codec.R, test-jws.R                       |
| JWS malformed and header-rule refusals    | hand corpus whose verdict is known by construction (`malformed_corpus()`)               | tests/testthat/test-codec.R                                   |
| JWS, JWE and JWK refusals                 | Wycheproof JOSE vectors, verdict for verdict                                            | gap #98                                                        |
| JWS compact emit                          | RFC 7520 §4.4, §4.5 and RFC 7515 A.2 reproduced byte for byte                           | tests/testthat/test-jws.R, test-rsa.R                         |
| JWS JSON emit                             | RFC 7520 §4.4 to §4.6, member order ignored                                             | tests/testthat/test-jws.R                                     |
| RFC 7797 unencoded payload                | RFC 7797 §4.1, §4.2 verified and reproduced: compact, flattened, detached               | tests/testthat/test-jws.R, test-codec.R                       |
| HS* verify and sign                       | RFC 7515 A.1, RFC 7520 §4.4 to §4.8; PyJWT tokens, signatures byte-identical            | tests/testthat/test-jws.R, test-oracle.R                      |
| RS* verify and sign                       | RFC 7515 A.2, RFC 7520 §4.1; PyJWT tokens, signatures byte-identical                    | tests/testthat/test-rsa.R, test-oracle.R                      |
| PS* verify                                | RFC 7520 §4.2 and §6; PyJWT PS256, PS384, PS512                                         | tests/testthat/test-rsa.R, test-oracle.R                      |
| ES* verify, raw r and s                   | RFC 7515 A.3, A.4, RFC 7520 §4.3; PyJWT ES256, ES384, ES512                             | tests/testthat/test-ec.R, test-oracle.R                       |
| Signature verify edge cases               | Wycheproof ECDSA P1363, RSA PKCS#1, RSA-PSS and HMAC verdicts                           | gap #99                                                        |
| PS*, ES* and JWT emit                     | PyJWT verifying what zujose signs                                                       | gap #100                                                        |
| JWE compact parse and decrypt             | RFC 7516 A.3, RFC 7520 §5 compact figures to their plaintexts                           | tests/testthat/test-jwe.R, test-jwe-gcm-pbes2.R               |
| JWE JSON parse and decrypt                | RFC 7516 A.4, RFC 7520 general and flattened figures, §5.13 three recipients            | tests/testthat/test-jwe.R, test-ec.R                          |
| JWE AAD from the received header bytes    | jwcrypto's non-canonical headers decrypt (`jwe-noncanonical.tsv`)                       | tests/testthat/test-jwe.R                                     |
| JWE compact emit                          | RFC 7516 A.3 byte for byte at a fixed CEK and IV; jwcrypto, dev, decrypts every pair    | tests/testthat/test-jwe.R, tools/jwe-oracle/                  |
| JWE JSON emit and parse                   | jwcrypto exchanging general and flattened tokens, `aad` and unprotected headers         | gap #101                                                        |
| JWE failure uniformity                    | one class and one message compared across causes and algorithms                         | tests/testthat/test-jwe.R, test-ec.R, test-aes.R              |
| AES key wrap, A*KW                        | RFC 3394 §4.1 to §4.6 both ways; RFC 7520 §5.8 wrapped key                              | tests/testthat/test-aes.R, test-jwe-gcm-pbes2.R               |
| A*GCMKW                                   | RFC 7520 §5.7 decrypted and wrap reproduced; jwcrypto, dev, for 128 and 192             | tests/testthat/test-jwe-gcm-pbes2.R, tools/jwe-oracle/        |
| PBES2-HS512+A256KW                        | RFC 7520 §5.3 decrypted; the wrap rebuilt from the RFC's factors                        | tests/testthat/test-jwe-gcm-pbes2.R                           |
| RSA-OAEP decrypt                          | RFC 7520 §5.2 and §6 to their plaintexts                                                | tests/testthat/test-rsa.R                                     |
| RSA1_5 decrypt                            | RFC 7520 §5.1 and §5.13; jwcrypto, dev, encrypting                                      | tests/testthat/test-rsa.R, test-ec.R, tools/jwe-oracle/       |
| RSA-OAEP and RSA-OAEP-256 encrypt         | round trip; jwcrypto, dev, decrypting                                                   | tests/testthat/test-rsa.R, tools/jwe-oracle/                  |
| ECDH-ES on P-256, P-384, P-521            | RFC 7518 App. C, RFC 7520 §5.4, §5.5, §5.13; App. C CEK and `epk` reproduced            | tests/testthat/test-ec.R                                      |
| ECDH-ES on X25519                         | RFC 8037 A.6 shared secret; round trip; jwcrypto, dev                                   | tests/testthat/test-ec.R, tools/jwe-oracle/                   |
| Concat KDF, one round                     | RFC 7518 App. C derived key; RFC 7520 §5.4, §5.5                                        | tests/testthat/test-ec.R                                      |
| A*CBC-HS*                                 | RFC 7518 App. B, all three sizes, ciphertext and tag; RFC 7516 A.3                      | tests/testthat/test-aes.R, test-jwe.R                         |
| A*GCM decrypt                             | RFC 7520 §5.6, §5.8 (A128GCM) and §5.2 (A256GCM)                                        | tests/testthat/test-jwe-gcm-pbes2.R, test-rsa.R               |
| PBES2-HS256, Concat KDF over 256 bits, A*GCM encrypt, A192* | RFC 7517 App. C every step; RFC 7516 A.1 reproduced; jwcrypto tokens (`jwe-vectors.tsv`) decrypted, reproduced, KDF keys equal | tests/testthat/test-jwe-gcm-pbes2.R, test-rsa.R, test-oracle.R |
| JWK import, every `kty`                   | RFC 7515, 7520 and 8037 keys give the RFCs' signatures, plaintexts and shared secrets   | tests/testthat/test-keys.R, test-rsa.R, test-ec.R             |
| JWK export, every `kty`                   | round trip for every RFC 7520 key; jwcrypto, dev, reads the exported set                | tests/testthat/test-keys.R, tools/jwe-oracle/                 |
| PEM import, RSA and EC                    | `cryptography`'s PEMs give keys that verify PyJWT's tokens                              | tests/testthat/test-oracle.R                                  |
| PEM export, RSA                           | identical to `cryptography`'s PKCS#8 and SPKI bytes                                     | tests/testthat/test-rsa.R                                     |
| PEM export, EC and X25519                 | identical to `cryptography`'s PKCS#8 and SPKI bytes for P-256, P-384, P-521 and X25519  | tests/testthat/test-ec.R                                      |
| JWK Set parse and emit                    | RFC 7520 keys as one set; RFC 7517 §5 skip rule; round trip                             | tests/testthat/test-keyset.R                                  |
| JWK Set parse, published sets             | RFC 7517 A.1, A.2, A.3 sets, every key's `kty`, `kid`, `use`, `alg` and members         | tests/testthat/test-keyset.R                                  |
| RFC 7638 thumbprint, RSA                  | RFC 7638 §3.1 value; RFC 9278 URI                                                       | tests/testthat/test-thumbprint.R                              |
| Thumbprint, EC, OKP and oct               | RFC 8037 A.3 value; jwcrypto's `thumbprint()` for P-256 to P-521, X25519, Ed25519, oct  | tests/testthat/test-thumbprint.R                              |
| JWT claim validation                      | RFC 7519 §3.1; hand straddles of `exp`, `nbf`, `iat` at the leeway                      | tests/testthat/test-jwt.R                                     |
| JWT claim verdicts                        | PyJWT's accept or reject over a grid of claims, times and leeways                       | gap #106                                                        |
| Nested JWT decode                         | RFC 7520 §6, PS256 inside RSA-OAEP, to its `iss`                                        | tests/testthat/test-rsa.R, test-jwt-encrypted.R               |
| Nested JWT emit                           | round trip                                                                              | tests/testthat/test-jwt-encrypted.R                           |
| `jose_peek()`                             | RFC 7519 headers and claims; RFC 7520 parts equal the decoded compact parts             | tests/testthat/test-peek.R                                    |
<!-- markdownlint-enable MD013 -->

## Limits

One row per limit the package enforces. "Straddled by" is the test of
`limit - 1`, `limit` and `limit + 1` on every path that reaches it.

<!-- markdownlint-disable MD013 -->
| Limit                                | Unit                                                    | Straddled by                 |
| ------------------------------------ | ------------------------------------------------------- | ---------------------------- |
| `token`                              | bytes of the serialized token                           | tests/testthat/test-limits.R |
| `header`                             | decoded bytes of each protected header                  | tests/testthat/test-limits.R |
| `payload`, Base64url                 | decoded payload bytes                                   | tests/testthat/test-limits.R |
| `payload`, `b64: false` and detached | payload bytes as received                               | tests/testthat/test-limits.R |
| `payload`, JWE                       | decoded ciphertext bytes, not plaintext                 | tests/testthat/test-limits.R |
| `signatures`                         | entries of `signatures`                                 | tests/testthat/test-limits.R |
| `recipients`                         | entries of `recipients`                                 | tests/testthat/test-limits.R |
| `keys`                               | keys tried for one token                                | tests/testthat/test-limits.R |
| `p2c`, decrypt                       | PBKDF2 iterations a header asks for                     | tests/testthat/test-limits.R |
| `p2c`, encrypt                       | iterations, 1000 to 2^32 - 1                            | tests/testthat/test-limits.R |
| `p2s`, at least 8                    | decoded salt bytes                                      | tests/testthat/test-limits.R |
| A*GCMKW `iv` 12 and `tag` 16         | decoded bytes, exact                                    | tests/testthat/test-limits.R |
| HMAC key at least the hash size      | key bytes, 32, 48 and 64                                | tests/testthat/test-limits.R |
| RSA modulus at least 2048            | modulus bits                                            | tests/testthat/test-limits.R |
| `leeway`                             | seconds, on `exp`, `nbf` and `iat`                      | tests/testthat/test-jwt.R    |
| `max_age`                            | seconds since `iat`, plus `leeway`                      | tests/testthat/test-limits.R |
| Nested JWT, one level                | levels of `cty: JWT`                                    | tests/testthat/test-jwt.R, test-limits.R |
| JSON nesting depth, from zujson      | nesting levels, 1000                                    | tests/testthat/test-limits.R |
<!-- markdownlint-enable MD013 -->
