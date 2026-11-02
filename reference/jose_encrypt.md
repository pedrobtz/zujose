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

Encryption generates a fresh content encryption key and initialization
vector for every message, so it needs cryptographic randomness from
zucrypt (\>= 0.2.0). Until that is installed it raises
`zujwt_unsupported_error`; decryption works without it.

## See also

[`jose_decrypt()`](https://pedrobtz.github.io/zujwt/reference/jose_decrypt.md).

## Examples

``` r
key <- jose_key_oct(as.raw(1:16), kid = "kek")
# Until zucrypt (>= 0.2.0) supplies randomness, this is unsupported.
try(jose_encrypt("secret", key, alg = "A128KW"))
#> Error in jose_encrypt("secret", key, alg = "A128KW") : 
#>   Encryption needs random keys and IVs from zucrypt (>= 0.2.0).
```
