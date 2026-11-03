# Encrypt a payload as a JWE

`jose_encrypt()` encrypts `plaintext` to one recipient, or to several
through
[`jose_recipient()`](https://pedrobtz.github.io/zujwt/reference/jose_recipient.md),
and returns the JWE in the compact, flattened JSON or general JSON
serialization (RFC 7516).

## Usage

``` r
jose_encrypt(
  plaintext,
  key,
  alg = NULL,
  enc = "A128CBC-HS256",
  header = NULL,
  unprotected = NULL,
  aad = NULL,
  format = c("compact", "flattened", "general")
)
```

## Arguments

- plaintext:

  The plaintext: a raw vector, or a single string taken as UTF-8 text.

- key:

  A `jose_key`, or a list of
  [`jose_recipient()`](https://pedrobtz.github.io/zujwt/reference/jose_recipient.md)
  objects for several recipients.

- alg:

  The key management algorithm, such as `"A256KW"` or `"dir"`. `NULL`
  takes the key's own `alg`.

- enc:

  The content encryption algorithm. `"A128CBC-HS256"` is the one RFC
  7518 requires every implementation to support.

- header:

  Further protected header members, as a named list.

- unprotected:

  Shared unprotected header members, as a named list. Only the JSON
  serializations carry them.

- aad:

  Additional authenticated data, as a raw vector or a string. Only the
  JSON serializations carry it.

- format:

  `"compact"`, `"flattened"` or `"general"`. Several recipients need
  `"general"`.

## Value

The JWE, as a single string.

## Details

Every message gets a fresh content encryption key and initialization
vector, drawn from the operating system's cryptographic random source
through zucrypt. They cannot be supplied: a reused IV or CEK breaks the
encryption. If the random source fails, the error is zucrypt's
`zucrypt_entropy_error`, and nothing is returned.

## See also

[`jose_decrypt()`](https://pedrobtz.github.io/zujwt/reference/jose_decrypt.md).

## Examples

``` r
key <- jose_key_generate("oct", alg = "A128KW", kid = "kek")
token <- jose_encrypt("secret", key)
token
#> [1] "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoia2VrIn0.8hkwGREUtesKQ9NpmgO-KTIqRSD2xXp2txs9JIpylVAof8wE-qZn3Q.rI78wkJ3TSZlCvKK5vnZ9Q.BPWwhlCRB9dvJbz6-MPixA.35ng3UheDYLWb5cXmrl6qg"
jose_decrypt(token, key, algorithms = "A128KW",
             encryptions = "A128CBC-HS256")
#> <jose_decrypted> A128KW with A128CBC-HS256, key "kek"
#> Header:
#>   alg: "A128KW"
#>   enc: "A128CBC-HS256"
#>   kid: "kek"
#> Plaintext: 6 bytes
```
