# Get started with zujose

zujose signs, verifies, encrypts and decrypts JOSE objects. This article
walks through the pieces in the order you meet them: keys, JSON Web
Tokens, signatures and encryption underneath, and reading a token you
have not checked yet.

``` r

library(zujose)
```

## The vocabulary

JOSE (JSON Object Signing and Encryption) is a family of standards:

- a **JWS** (RFC 7515) is a signed payload;
- a **JWE** (RFC 7516) is an encrypted payload;
- a **JWK** (RFC 7517) is a key written as JSON, and a JWK Set is a list
  of them;
- a **JWT** (RFC 7519) is a set of claims, such as who the token is
  about and when it expires, carried as the payload of a JWS or a JWE.

Each comes in a *compact* serialization, the familiar
`xxxxx.yyyyy.zzzzz`, and a JSON one. RFC 7518 lists the algorithms.
zujose names each function after the object it works on:
[`jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jwt_encode.md),
[`jws_sign()`](https://pedrobtz.github.io/zujose/reference/jws_sign.md),
[`jwe_decrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_decrypt.md),
[`jwk_generate()`](https://pedrobtz.github.io/zujose/reference/jwk_generate.md).
The token or payload is the first argument and the key the second.

## Keys

A key is a `jwk`. A symmetric key, of type `oct`, is a secret shared by
whoever signs and whoever verifies. Generate one for the algorithm you
mean to use, and it is the right length:

``` r

hmac <- jwk_generate("oct", alg = "HS256", kid = "hmac-1")
hmac
#> <jwk> oct, 256 bits
#>   kid "hmac-1"
#>   alg HS256
#>   private: yes (not shown)
```

Printing never shows the secret. An existing secret, as raw bytes, is
wrapped with
[`jwk_oct()`](https://pedrobtz.github.io/zujose/reference/jwk_oct.md). A
password is not a key: turn it into one with a key derivation function,
or use PBES2 encryption, which does that for you.

Public-key algorithms need a key pair. zujose makes RSA keys and
elliptic-curve keys on P-256, P-384, P-521 and X25519:

``` r

signer <- jwk_generate("EC", crv = "P-256", alg = "ES256", kid = "ec-1")
signer
#> <jwk> EC, 256 bits
#>   kid "ec-1"
#>   alg ES256
#>   private: yes (not shown)
```

[`as_jwk()`](https://pedrobtz.github.io/zujose/reference/as_jwk.md)
reads a key from JWK text or from PEM, and
[`jwk_json()`](https://pedrobtz.github.io/zujose/reference/jwk_json.md)
and
[`jwk_pem()`](https://pedrobtz.github.io/zujose/reference/jwk_pem.md)
write one. Both write only the public part unless you ask for the
private one:

``` r

jwk_json(signer)
#> [1] "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"JLFJAGSfpM3WJvDkYEOJXv6f4iANzHp9CB5trBuXhrA\",\"y\":\"7x6f9WGoAlSn1eqEQFLW9QQ7A5gehXS0j9QYC8WhpAA\",\"kid\":\"ec-1\",\"alg\":\"ES256\"}"
```

A key set holds several keys. Its JWK Set text is what an identity
provider publishes, and what a client reads to verify the provider’s
tokens:

``` r

keys <- jwk_set(signer, jwk_generate("RSA", alg = "RS256", kid = "rsa-1"))
keys
#> <jwk_set> 2 keys
#>   EC "ec-1" ES256
#>   RSA "rsa-1" RS256
cat(jwk_json(keys))
#> {"keys":[{"kty":"EC","crv":"P-256","x":"JLFJAGSfpM3WJvDkYEOJXv6f4iANzHp9CB5trBuXhrA","y":"7x6f9WGoAlSn1eqEQFLW9QQ7A5gehXS0j9QYC8WhpAA","kid":"ec-1","alg":"ES256"},{"kty":"RSA","n":"my53jW0pnLyWY7Z9mBvgD1ZeoCmHBzKTZaz3BjPdxpDPN2xAeMNqjwpFUnplS1s1jgCv4UWrD5CMvCiczdX4qK3_NhNVu2AWOAppMhJhdtL1SNoqktSqM76-1NAr-QSODnu-WxMNEG7Vfo23wHoYxkJKfbP3xZTpUUj6UTM9IIATkV4a8KH4wK-aoigqCMYtofOE-QxgY3VjIXDmr84NDm1l1pXll9MGYX5lD9LF4TFK-26qtgFDZx0EStFV4NSGPnGY-wIegZ0bVukoanfRrbMG8llC9805T-Y9fvLF-PtR7PMUyllrB-SfAqxjvmJBr9jiGCQg_8SOlpV7n6-TQQ","e":"AQAB","kid":"rsa-1","alg":"RS256"}]}
```

[`as_jwk_set()`](https://pedrobtz.github.io/zujose/reference/jwk_set.md)
reads that text back. A key in a set is picked by the `kid` in a token’s
header. Two more tools help with naming keys:
[`jwk_with_kid()`](https://pedrobtz.github.io/zujose/reference/jwk_with_kid.md)
names a key by its RFC 7638 thumbprint, which needs no registry, and
[`jwk_thumbprint()`](https://pedrobtz.github.io/zujose/reference/jwk_thumbprint.md)
computes the thumbprint itself.

Keys live in ordinary R memory, which R can copy and cannot wipe. See
the “Secrets in memory” section of
[`?jwk_oct`](https://pedrobtz.github.io/zujose/reference/jwk_oct.md) for
what that means.

## JSON Web Tokens

[`jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jwt_encode.md)
signs a list of claims. `expires_in` sets `exp`, and `iat` is added for
you:

``` r

jwt <- jwt_encode(
  list(iss = "https://auth.example", sub = "user-17", aud = "orders-api"),
  signer,
  expires_in = 600
)
```

[`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
checks the token in one call. You say which algorithms you accept; there
is no default, so a token cannot choose a weaker one for you. The key
must fit the algorithm. Then the claims are checked: `exp` is required
by default, `nbf` and `iat` are checked when present, with a leeway of
60 seconds, and `audience`, `issuer` and `subject` are matched when you
give them:

``` r

claims <- jwt_decode(
  jwt,
  jwk_public(signer),
  algorithms = "ES256",
  audience = "orders-api",
  issuer = "https://auth.example"
)
claims
#> <jwt_claims> verified ES256, key "ec-1"
#>   iss: "https://auth.example"
#>   sub: "user-17"
#>   aud: "orders-api"
#>   exp: 2026-11-03 13:53:38 UTC
#>   iat: 2026-11-03 13:43:38 UTC
```

`claims` takes per-claim expectations, as a value or as a function that
must return `TRUE`, and `validate` takes one function of all the claims:

``` r

jwt_decode(
  jwt,
  jwk_public(signer),
  algorithms = "ES256",
  audience = "orders-api",
  claims = list(sub = function(sub) startsWith(sub, "user-"))
)$sub
#> [1] "user-17"
```

When the same checks apply to every request,
[`jwt_decoder()`](https://pedrobtz.github.io/zujose/reference/jwt_decoder.md)
fixes them once and returns a function of the token:

``` r

check <- jwt_decoder(
  key = jwk_public(keys),
  algorithms = c("ES256", "RS256"),
  audience = "orders-api",
  issuer = "https://auth.example"
)
check(jwt)$sub
#> [1] "user-17"
```

## When a check fails

Every error is a condition whose class says what failed, all inheriting
from `zujose_error`. Catch the class, not the message:

``` r

expired <- jwt_encode(list(sub = "user-17"), hmac, expires_in = -3600)
tryCatch(
  jwt_decode(expired, hmac, algorithms = "HS256"),
  zujose_expired_error = function(e) paste("expired at", e$time)
)
#> [1] "expired at 2026-11-03 12:43:38"
```

A token signed with an algorithm you did not allow is a policy error,
raised before any cryptography is done:

``` r

jwt_decode(jwt, jwk_public(signer), algorithms = "RS256")
#> Error in `jwt_decode()`:
#> ! The token's algorithm is not in `algorithms`.
```

[`?zujose_error`](https://pedrobtz.github.io/zujose/reference/zujose_error.md)
lists every class and the fields each carries.

## Signatures: JWS

A JWT is a JWS whose payload is a JSON object.
[`jws_sign()`](https://pedrobtz.github.io/zujose/reference/jws_sign.md)
and
[`jws_verify()`](https://pedrobtz.github.io/zujose/reference/jws_verify.md)
sign and verify any payload, given as a string or as raw bytes:

``` r

token <- jws_sign("Order 1042 shipped.", hmac)
verified <- jws_verify(token, hmac, algorithms = "HS256")
rawToChar(verified$payload)
#> [1] "Order 1042 shipped."
```

`format = "flattened"` or `"general"` writes the JSON serialization, and
several signers, made with
[`jws_signer()`](https://pedrobtz.github.io/zujose/reference/jws_signer.md),
sign one payload together:

``` r

token <- jws_sign(
  "Order 1042 shipped.",
  list(jws_signer(hmac), jws_signer(signer)),
  format = "general"
)
```

By default every signature must verify. A recipient that holds only one
of the keys asks for any one signature instead:

``` r

jws_verify(
  token,
  jwk_public(signer),
  algorithms = "ES256",
  require = "any"
)$kid
#> [1] "ec-1"
```

## Encryption: JWE

A JWE is encrypted in two layers: a random content encryption key
encrypts the payload (`enc`), and the key management algorithm (`alg`)
delivers that key to the recipient. To encrypt for a public key, use the
recipient’s public key:

``` r

recipient <- jwk_generate("RSA", kid = "rsa-enc")
jwe <- jwe_encrypt(
  "card ending 4242",
  jwk_public(recipient),
  alg = "RSA-OAEP-256",
  enc = "A256GCM"
)
```

Decrypting names both the key management and the content encryption
algorithms you accept:

``` r

out <- jwe_decrypt(
  jwe,
  recipient,
  algorithms = "RSA-OAEP-256",
  encryptions = "A256GCM"
)
rawToChar(out$plaintext)
#> [1] "card ending 4242"
```

Every decryption failure raises `zujose_decrypt_error` with the same
message, whatever went wrong, so a failure tells an attacker nothing
about the key.

A password encrypts through PBES2, which derives the key from it. Give
the password to
[`jwk_oct()`](https://pedrobtz.github.io/zujose/reference/jwk_oct.md) as
bytes:

``` r

password <- jwk_oct(charToRaw("correct horse battery staple"))
jwe <- jwe_encrypt(
  "backup notes",
  password,
  alg = "PBES2-HS256+A128KW",
  enc = "A128GCM"
)
rawToChar(jwe_decrypt(jwe, password, "PBES2-HS256+A128KW", "A128GCM")$plaintext)
#> [1] "backup notes"
```

## Encrypted JWTs

A JWT can be signed and then encrypted, so that only the recipient can
read the claims. Compose the two steps:

``` r

nested <- jwt_encode(list(sub = "user-17"), signer, expires_in = 600) |>
  jwe_encrypt(
    jwk_public(recipient),
    alg = "RSA-OAEP-256",
    enc = "A256GCM",
    header = list(cty = "JWT")
  )
```

[`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
accepts an encrypted JWT only when you say how to decrypt it, with
[`jwe_decryption()`](https://pedrobtz.github.io/zujose/reference/jwe_decryption.md).
Without it, a JWE where a signed token was expected is refused:

``` r

jwt_decode(
  nested,
  jwk_public(signer),
  algorithms = "ES256",
  decrypt = jwe_decryption(recipient, "RSA-OAEP-256", "A256GCM")
)$sub
#> [1] "user-17"
```

## Reading a token without checking it

Sometimes you need to look inside a token before you can check it, for
example to read its `kid` or `iss` and choose a key.
[`jose_peek()`](https://pedrobtz.github.io/zujose/reference/jose_peek.md)
decodes every part of a token and verifies nothing:

``` r

jose_peek(jwt)
#> <jose_unverified> JWS, compact serialization
#> ! Not verified: nothing here can be trusted.
#> Header:
#>   alg: "ES256"
#>   kid: "ec-1"
#>   typ: "JWT"
#> Claims:
#>   iss: "https://auth.example"
#>   sub: "user-17"
#>   aud: "orders-api"
#>   exp: 1793714018
#>   iat: 1793713418
#> Signature: 64 bytes
```

Its result is classed `jose_unverified` and says so. Use it to decide
which key or policy to apply, never to decide whether to trust the
token.

## Limits and supported algorithms

Every function that reads a token checks its size, its header, the
number of signatures or recipients and the PBES2 iteration count against
[`jose_limits()`](https://pedrobtz.github.io/zujose/reference/jose_limits.md)
before decoding anything. The defaults suit ordinary tokens; raise them
only for a source you trust.

[`zujose_info()`](https://pedrobtz.github.io/zujose/reference/zujose_info.md)
lists every algorithm and whether the installed zucrypt provides it:

``` r

head(zujose_info())
#>   algorithm      kind available zucrypt
#> 1     HS256 signature      TRUE   0.1.0
#> 2     HS384 signature      TRUE   0.1.0
#> 3     HS512 signature      TRUE   0.1.0
#> 4     RS256 signature      TRUE   0.4.0
#> 5     RS384 signature      TRUE   0.4.0
#> 6     RS512 signature      TRUE   0.4.0
```
