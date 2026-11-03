# One signer of a multi-signature JWS

`jws_signer()` pairs a key with its algorithm and headers, for
[`jws_sign()`](https://pedrobtz.github.io/zujose/reference/jws_sign.md)
to produce a general JSON serialization with several signatures.

## Usage

``` r
jws_signer(key, alg = NULL, header = NULL, unprotected = NULL)
```

## Arguments

- key:

  A `jwk`.

- alg:

  The signature algorithm, such as `"HS256"` or `"RS256"`. `NULL` takes
  the key's own `alg`.

- header:

  Further protected header members, as a named list.

- unprotected:

  Unprotected header members, as a named list. Only the JSON
  serializations carry them.

## Value

A `jws_signer`.

## Examples

``` r
k1 <- jwk_oct(as.raw(1:32), kid = "a")
k2 <- jwk_oct(as.raw(33:96), kid = "b")
jws_sign(
  "hello",
  list(jws_signer(k1, "HS256"), jws_signer(k2, "HS512")),
  format = "general"
)
#> [1] "{\"payload\":\"aGVsbG8\",\"signatures\":[{\"protected\":\"eyJhbGciOiJIUzI1NiIsImtpZCI6ImEifQ\",\"signature\":\"cwKbXNFoQDh5wNiPLZlr-5DtmBT1gF--MxpUjw-wA7s\"},{\"protected\":\"eyJhbGciOiJIUzUxMiIsImtpZCI6ImIifQ\",\"signature\":\"2kNGKq2iYw-mNa5BYg6rKSpJ0PQ2eDJ1giNxfGyPd9kanTN71FroqFGK_Tr0MY65tyh3meevtjAZt_Ct08nrbw\"}]}"
```
