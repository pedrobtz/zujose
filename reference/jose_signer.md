# One signer of a multi-signature JWS

`jose_signer()` pairs a key with its algorithm and headers, for
[`jose_sign()`](https://pedrobtz.github.io/zujwt/reference/jose_sign.md)
to produce a general JSON serialization with several signatures.

## Usage

``` r
jose_signer(key, alg = NULL, header = NULL, unprotected = NULL)
```

## Arguments

- key:

  A `jose_key`.

- alg:

  The signature algorithm, such as `"HS256"`. `NULL` takes the key's own
  `alg`.

- header:

  Further protected header members, as a named list.

- unprotected:

  Unprotected header members, as a named list. Only the JSON
  serializations carry them.

## Value

A `jose_signer`.

## Examples

``` r
k1 <- jose_key_oct(as.raw(1:32), kid = "a")
k2 <- jose_key_oct(as.raw(33:96), kid = "b")
jose_sign(
  "hello",
  list(jose_signer(k1, "HS256"), jose_signer(k2, "HS512")),
  format = "general"
)
#> [1] "{\"payload\":\"aGVsbG8\",\"signatures\":[{\"protected\":\"eyJhbGciOiJIUzI1NiIsImtpZCI6ImEifQ\",\"signature\":\"cwKbXNFoQDh5wNiPLZlr-5DtmBT1gF--MxpUjw-wA7s\"},{\"protected\":\"eyJhbGciOiJIUzUxMiIsImtpZCI6ImIifQ\",\"signature\":\"2kNGKq2iYw-mNa5BYg6rKSpJ0PQ2eDJ1giNxfGyPd9kanTN71FroqFGK_Tr0MY65tyh3meevtjAZt_Ct08nrbw\"}]}"
```
