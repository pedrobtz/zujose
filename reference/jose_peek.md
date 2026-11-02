# Look inside a token without verifying it

`jose_peek()` parses a JWS or JWE, in any serialization, and returns its
headers and, for a JWS, its payload. **Nothing is verified.** The result
is classed `jose_unverified` and says so when printed. Use it to decide
which key or policy to apply, or to debug, never to make a decision that
trusts the token. `jose_verify()` and `jose_decrypt()` are the functions
that check a token.

## Usage

``` r
jose_peek(token, limits = jose_limits())
```

## Arguments

- token:

  A token: a compact serialization, or the text of a JSON serialization.

- limits:

  Resource limits, from
  [`jose_limits()`](https://pedrobtz.github.io/zujwt/reference/jose_limits.md).

## Value

A list of class `jose_unverified` with:

- `type`: `"JWS"` or `"JWE"`.

- `serialization`: `"compact"`, `"flattened"` or `"general"`.

- `headers`: one header per signature or recipient, each the union of
  the protected and unprotected headers.

- `payload`: for a JWS, the payload as a raw vector; `NULL` for a JWE or
  a detached payload.

- `claims`: the payload parsed as a list when it is a JSON object, as in
  a JWT; otherwise `NULL`.

## Details

The token must still be well formed: strict unpadded Base64url, headers
that are JSON objects without repeated members, and the rules on `crit`
and `b64` (RFC 7515, RFC 7797). A malformed token raises
`zujwt_parse_error`.

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
```
