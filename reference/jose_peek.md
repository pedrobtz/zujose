# Look inside a token without verifying it

`jose_peek()` parses a JWS or JWE, in any serialization, and returns its
headers and, for a JWS, its payload. **Nothing is verified.** The result
is classed `jose_unverified` and says so when printed. Use it to decide
which key or policy to apply, or to debug, never to make a decision that
trusts the token.
[`jws_verify()`](https://pedrobtz.github.io/zujose/reference/jws_verify.md)
and
[`jwe_decrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_decrypt.md)
are the functions that check a token.

## Usage

``` r
jose_peek(token, limits = jose_limits())
```

## Arguments

- token:

  A token: a compact serialization, or the text of a JSON serialization.

- limits:

  Resource limits, from
  [`jose_limits()`](https://pedrobtz.github.io/zujose/reference/jose_limits.md).

## Value

A list of class `jose_unverified` with:

- `type`: `"JWS"` or `"JWE"`.

- `serialization`: `"compact"`, `"flattened"` or `"general"`.

- `headers`: one header per signature or recipient, each the union of
  the protected and unprotected headers.

- `payload`: for a JWS, the payload as a raw vector; `NULL` for a JWE or
  a detached payload. In the compact serialization an empty payload part
  is a detached payload.

- `claims`: the payload parsed as a list when it is a JSON object, as in
  a JWT; otherwise `NULL`.

A JWS also has, one element per signature:

- `signatures`: each signature, as a raw vector.

- `signing_input`: the bytes each signature covers, as a raw vector;
  `NULL` for a detached payload.

A JWE also has:

- `encrypted_keys`: one encrypted key per recipient, as a raw vector,
  empty for `dir` and `ECDH-ES`.

- `iv`, `ciphertext` and `tag`: raw vectors.

- `aad`: the additional authenticated data as a raw vector, or `NULL`.

## Details

The token must still be well formed: strict unpadded Base64url, headers
that are JSON objects without repeated members, and the rules on `crit`
and `b64` (RFC 7515, RFC 7797). A malformed token raises
`zujose_parse_error`.

## Examples

``` r
token <- paste0(
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
  "eyJzdWIiOiJ1MSIsImV4cCI6MTMwMDgxOTM4MH0.",
  "c2lnbmF0dXJl"
)
jose_peek(token)
#> <jose_unverified> JWS, compact serialization
#> ! Not verified: nothing here can be trusted.
#> Header:
#>   alg: "HS256"
#>   typ: "JWT"
#> Claims:
#>   sub: "u1"
#>   exp: 1300819380
#> Signature: 9 bytes
```
