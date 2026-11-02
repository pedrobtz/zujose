# Verify a JWS

`jose_verify()` checks a JWS in any serialization and returns its
payload. The caller names the algorithms it accepts: a token whose `alg`
is not in `algorithms` is refused before any key is used, and the key
must fit the algorithm (RFC 8725). There is no default and no way to
accept `"none"`.

## Usage

``` r
jose_verify(
  token,
  key,
  algorithms,
  payload = NULL,
  require = c("all", "any"),
  limits = jose_limits()
)
```

## Arguments

- token:

  The JWS: a compact serialization, or JSON text.

- key:

  A `jose_key`, a `jose_keyset`, or a function of the header returning
  one.

- algorithms:

  The signature algorithms to accept, such as `"HS256"`.

- payload:

  For a detached payload (RFC 7515 Appendix F), the payload: a raw
  vector or a single string.

- require:

  With several signatures, whether `"all"` must verify (the default) or
  `"any"` one is enough. With `"any"`, signatures whose algorithm is not
  in `algorithms` are skipped.

- limits:

  Resource limits, from
  [`jose_limits()`](https://pedrobtz.github.io/zujwt/reference/jose_limits.md).

## Value

A list of class `jose_verified` with `payload` (raw), `header` (the
protected and unprotected header of the first verified signature),
`protected` (its protected part), `kid` and `alg` (of the key and
algorithm that verified it), and `signatures`, one such entry per
verified signature.

## Details

`key` may be a single key, a key set, from which the token's `kid`
selects, or a function that receives the token's header (a named list)
and returns either. Keys or URLs inside the token (`jwk`, `jku`, `x5c`,
`x5u`) are never used.

## Examples

``` r
key <- jose_key_oct(as.raw(1:32), kid = "k1")
token <- jose_sign("hello", key, alg = "HS256")
jose_verify(token, key, algorithms = "HS256")
#> <jose_verified> HS256, key "k1"
#> Header:
#>   alg: "HS256"
#>   kid: "k1"
#> Payload: 5 bytes

# The token's algorithm must be one you allow.
try(jose_verify(token, key, algorithms = "HS512"))
#> Error in jose_verify(token, key, algorithms = "HS512") : 
#>   The token's algorithm is not in `algorithms`.
```
