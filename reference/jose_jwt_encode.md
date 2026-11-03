# Encode a JWT

`jose_jwt_encode()` signs a claims set as a JSON Web Token (RFC 7519),
in the compact serialization.

## Usage

``` r
jose_jwt_encode(
  claims,
  key,
  alg = NULL,
  header = list(typ = "JWT"),
  expires_in = NULL,
  not_before = NULL,
  issued_at = TRUE,
  jti = FALSE
)
```

## Arguments

- claims:

  The claims, as a named list. It may be empty.

- key:

  A `jose_key`, or a list of
  [`jose_signer()`](https://pedrobtz.github.io/zujwt/reference/jose_signer.md)
  objects for several signatures.

- alg:

  The signature algorithm, such as `"HS256"` or `"RS256"`. `NULL` takes
  the key's own `alg`.

- header:

  Protected header members. The default declares `typ: "JWT"`.

- expires_in:

  Seconds, or a `difftime`, until the token expires. Sets `exp`.

- not_before:

  Seconds, or a `difftime`, before the token becomes valid. Sets `nbf`.

- issued_at:

  Whether to set `iat` to now, unless `claims` sets it.

- jti:

  Whether to add a random `jti`, 128 bits from the operating system's
  random source as Base64url, unless `claims` sets it.

## Value

The JWT, as a single string.

## Details

Times may be given as `POSIXct` for `exp`, `nbf` and `iat`, and are
written as NumericDate, whole seconds since 1970. `expires_in` and
`not_before` count from now.

## See also

[`jose_jwt_decode()`](https://pedrobtz.github.io/zujwt/reference/jose_jwt_decode.md)
to check one.

## Examples

``` r
key <- jose_key_oct(as.raw(1:32), kid = "k1")
jwt <- jose_jwt_encode(list(sub = "u1", aud = "api"), key, "HS256",
                       expires_in = 3600)
jose_jwt_decode(jwt, key, algorithms = "HS256", audience = "api")
#> <jose_claims> verified HS256, key "k1"
#>   sub: "u1"
#>   aud: "api"
#>   exp: 2026-11-03 11:36:21 UTC
#>   iat: 2026-11-03 10:36:21 UTC
```
