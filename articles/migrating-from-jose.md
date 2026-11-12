# Migrating from jose

The CRAN package [jose](https://cran.r-project.org/package=jose) reads
and writes JWKs and encodes and decodes JWTs on top of OpenSSL. This
article maps its functions to zujose’s and explains what changes. zujose
does not mirror jose’s API: the differences below are the point of the
move, and a compatibility layer would hide them.

``` r

library(zujose)
```

## Function by function

| jose 2.0 | zujose |
|----|----|
| `jwt_claim(iss, sub, aud, exp, ...)` | a plain named list; `expires_in` and `not_before` in [`jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jwt_encode.md) set `exp` and `nbf` |
| `jwt_encode_hmac(claim, secret, size = 256)` | `jwt_encode(claims, jwk_oct(secret), alg = "HS256")` |
| `jwt_decode_hmac(jwt, secret)` | `jwt_decode(jwt, jwk_oct(secret), algorithms = "HS256")` |
| `jwt_encode_sig(claim, key, size = 256)` | `jwt_encode(claims, as_jwk(pem), alg = "RS256")`, or `"ES256"`, `"PS256"`… |
| `jwt_decode_sig(jwt, pubkey)` | `jwt_decode(jwt, as_jwk(pem), algorithms = "RS256")` |
| `jwt_split(jwt)` | `jose_peek(jwt)` |
| `jwk_read(x)`, `read_jwk(x)` | `as_jwk(x)`, or `as_jwk_set(x)` for a JWK Set |
| `jwk_write(x)`, `write_jwk(x)` | `jwk_json(x)`; `jwk_pem(x)` for PEM |
| `base64url_encode(x)`, `base64url_decode(x)` | `zuutf::base64_encode(x, url = TRUE, pad = FALSE)`, `zuutf::base64_decode(x, url = TRUE)` |

Some names look alike across the two packages, `jwt_encode_hmac()` and
[`jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jwt_encode.md)
for one, but no zujose function has the same name as a jose function, so
both packages can be attached at once.

zujose also covers what jose does not: JWE, the JSON serializations,
detached and unencoded payloads (RFC 7797), key sets, thumbprints, and
encrypted JWTs.

## What changes

### You name the algorithms

`jwt_decode_hmac()` and `jwt_decode_sig()` take the algorithm from the
token’s header, limited only by the type of key.
[`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
has an `algorithms` argument with no default, and refuses any other
algorithm before it does any cryptography. This closes algorithm
confusion, where a token picks a weaker algorithm than the one you meant
(RFC 8725, section 2.1).

### Claims are checked, and `exp` is required

jose checks `exp` and `nbf` when a token has them. zujose checks them
too, with the same 60 second leeway, and also:

- requires `exp` by default (`required = "exp"`), so a token that never
  expires is refused unless you set `required = character()`;
- checks `iat` is not in the future, and `max_age` when you give one;
- matches `aud`, `iss` and `sub` against `audience`, `issuer` and
  `subject`, and any claim against `claims`.

### Keys are typed

jose takes a secret as a string or raw vector and a public key as an
openssl key object. zujose takes a `jwk` built from raw bytes, JWK text
or PEM. A string is not taken as a secret, because a password is not a
key:

``` r

secret <- charToRaw("a shared secret of at least 32 bytes!")
key <- jwk_oct(secret)
```

A key may name its one algorithm with `alg`, and is then refused for any
other.

### Errors have classes

jose signals errors with [`stop()`](https://rdrr.io/r/base/stop.html)
and a message. zujose raises conditions classed by cause, such as
`zujose_expired_error` or `zujose_audience_error`, all inheriting from
`zujose_error`. Catch the class, not the text;
[`?zujose_error`](https://pedrobtz.github.io/zujose/reference/zujose_error.md)
lists them.

## A worked example

A service that used jose to issue and check HMAC tokens:

``` r

library(jose)
secret <- charToRaw("a shared secret of at least 32 bytes!")
jwt <- jwt_encode_hmac(
  jwt_claim(sub = "user-17", aud = "orders-api", exp = Sys.time() + 600),
  secret = secret
)
claims <- jwt_decode_hmac(jwt, secret = secret)
stopifnot(claims$aud == "orders-api")
```

does the same with zujose like this:

``` r

key <- jwk_oct(secret, alg = "HS256")
jwt <- jwt_encode(
  list(sub = "user-17", aud = "orders-api"),
  key,
  expires_in = 600
)
claims <- jwt_decode(jwt, key, algorithms = "HS256", audience = "orders-api")
claims$sub
#> [1] "user-17"
```

The audience check moves into the decode call, where it cannot be
forgotten.

Both packages write standard JWTs, so tokens already issued keep working
after the move, with one exception: a token without `exp` is refused
unless you change `required`. zujose’s tests check its JWTs against
tokens made by PyJWT, an independent implementation, for every signature
algorithm.

To verify tokens from an OpenID Connect provider, read its JWK Set into
a key set; [Verifying tokens against a
JWKS](https://pedrobtz.github.io/zujose/articles/jwks-resolver.md) shows
how to fetch and cache it.
