
<!-- README.md is generated from README.Rmd. Please edit that file -->

# zujose

<!-- badges: start -->

[![Lifecycle:
experimental](https://img.shields.io/badge/lifecycle-experimental-orange.svg)](https://lifecycle.r-lib.org/articles/stages.html#experimental)
[![R-CMD-check](https://github.com/pedrobtz/zujose/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/pedrobtz/zujose/actions/workflows/R-CMD-check.yaml)
[![coverage](https://raw.githubusercontent.com/pedrobtz/zujose/main/.github/badges/coverage.svg)](https://github.com/pedrobtz/zujose/actions/workflows/coverage.yaml)
<!-- badges: end -->

R code that talks to OAuth 2.0 and OpenID Connect providers, or that
issues tokens from a Shiny or Plumber app, has to sign, check and
decrypt JSON Web Tokens. Getting that right is mostly about what a
library refuses: a token that names its own algorithm, a key smuggled in
its header, an expired claim that nobody looked at.

zujose implements the JOSE standards, JWS, JWE, JWK and JWT ([RFC
7515](https://www.rfc-editor.org/info/rfc7515/) to
[7519](https://www.rfc-editor.org/info/rfc7519/)), in both the compact
and the JSON serializations, with the defaults of [RFC
8725](https://www.rfc-editor.org/info/rfc8725/), the JWT best current
practices.

- **You name the algorithms.** Every function that checks a token takes
  an `algorithms` argument with no default, and the key must agree with
  it. `none` does not exist.
- **Claims are checked in the same call.** `jwt_decode()` verifies the
  signature and then `exp`, `nbf`, `aud`, `iss` and whatever else you
  ask for. There is no second step to forget.
- **Keys come only from you.** A key in a token’s header is never used,
  and zujose never fetches anything.
- **Every algorithm of RFC 7518 but `none`**: HMAC, RSA, RSA-PSS and
  ECDSA signatures; AES key wrap, AES-GCM key wrap, PBES2, RSA-OAEP and
  ECDH-ES (including X25519) key management; AES-CBC-HMAC and AES-GCM
  content encryption. `RSA1_5` is accepted for decryption only.
- **Pure R.** zujose has no compiled code. The cryptography comes from
  [zucrypt](https://github.com/pedrobtz/zucrypt), so no system library
  is needed.

## Installation

zujose is not on CRAN yet. Install the development version from GitHub,
which also installs the development version of zucrypt it needs:

``` r
# install.packages("pak")
pak::pak("pedrobtz/zujose")
```

## Usage

``` r
library(zujose)
```

An API that issues its own tokens needs a key. This one is a random
256-bit HMAC key, meant for `HS256` only:

``` r
key <- jwk_generate("oct", alg = "HS256", kid = "api-2026")
key
#> <jwk> oct, 256 bits
#>   kid "api-2026"
#>   alg HS256
#>   private: yes (not shown)
```

Sign a set of claims as a JWT that expires in an hour:

``` r
jwt <- jwt_encode(
  list(sub = "user-17", aud = "orders-api"),
  key,
  expires_in = 3600
)
jwt
#> [1] "eyJhbGciOiJIUzI1NiIsImtpZCI6ImFwaS0yMDI2IiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyLTE3IiwiYXVkIjoib3JkZXJzLWFwaSIsImV4cCI6MTc5MzcyMDMzNywiaWF0IjoxNzkzNzE2NzM3fQ.clyCMihuhOcj-V6rpCYuKviH5qpBPOEN5zLUFSpq97Y"
```

Checking it names the algorithm and the audience. The result is the
claims, with the times as `POSIXct`:

``` r
claims <- jwt_decode(jwt, key, algorithms = "HS256", audience = "orders-api")
claims$sub
#> [1] "user-17"
claims$exp
#> [1] "2026-11-03 15:38:57 UTC"
```

A token meant for another service is refused:

``` r
jwt_decode(jwt, key, algorithms = "HS256", audience = "billing-api")
#> Error in `jwt_decode()`:
#> ! The token is not for this `audience`.
```

Each failure has a class of its own, so code can catch one cause without
reading the message:

``` r
tryCatch(
  jwt_decode(jwt, key, algorithms = "HS256", audience = "billing-api"),
  zujose_audience_error = function(e) "403: wrong audience"
)
#> [1] "403: wrong audience"
```

Encryption takes a key of its own, because a key fits only the
algorithms it is for. This one wraps the content key of a JWE with AES
key wrap, and the content is encrypted with AES-GCM:

``` r
kek <- jwk_generate("oct", alg = "A256KW")
jwe <- jwe_encrypt("account 42: balance 100", kek, enc = "A256GCM")
rawToChar(jwe_decrypt(jwe, kek, "A256KW", "A256GCM")$plaintext)
#> [1] "account 42: balance 100"
```

Each function is named after the object it works on, `jwt_*`, `jws_*`,
`jwe_*` or `jwk_*`; the token or payload comes first and the key second;
and a token is only ever read without being checked by `jose_peek()`,
whose result says so when printed.

## Learn more

- [Get started](https://pedrobtz.github.io/zujose/articles/zujose.html):
  keys and key sets, JWS, JWE, JWT and reading a token.
- [Migrating from
  jose](https://pedrobtz.github.io/zujose/articles/migrating-from-jose.html):
  the `jose` functions and their zujose counterparts.
- [Verifying tokens against a
  JWKS](https://pedrobtz.github.io/zujose/articles/jwks-resolver.html):
  a resolver that fetches and caches an OpenID provider’s keys with
  httr2.
- [Reference](https://pedrobtz.github.io/zujose/reference/): every
  function, and the conditions zujose raises (`?zujose_error`).

## Related work

zujose is checked against the [RFC
7520](https://www.rfc-editor.org/info/rfc7520/) cookbook and the vectors
of RFCs 7515 to 7518, 7638, 7797 and 8037. Its JWS and JWT code is
checked against tokens made by
[PyJWT](https://github.com/jpadilla/pyjwt), and its JWE code against
[jwcrypto](https://github.com/latchset/jwcrypto) in both directions. The
CRAN package [jose](https://cran.r-project.org/package=jose) covers JWK,
JWS and JWT on top of OpenSSL.
