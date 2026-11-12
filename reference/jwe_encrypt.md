# Encrypt a payload as a JWE

`jwe_encrypt()` encrypts `plaintext` to one recipient, or to several
through
[`jwe_recipient()`](https://pedrobtz.github.io/zujose/reference/jwe_recipient.md),
and returns the JWE in the compact, flattened JSON or general JSON
serialization (RFC 7516).

## Usage

``` r
jwe_encrypt(
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

  A `jwk`, or a list of
  [`jwe_recipient()`](https://pedrobtz.github.io/zujose/reference/jwe_recipient.md)
  objects for several recipients.

- alg:

  The key management algorithm, such as `"A256KW"`, `"A256GCMKW"`,
  `"PBES2-HS256+A128KW"` or `"dir"`. `NULL` takes the key's own `alg`.

- enc:

  The content encryption algorithm. `"A128CBC-HS256"` is the one RFC
  7518 requires every implementation to support.

- header:

  Further protected header members, as a named list. For `PBES2-*`,
  `p2c` sets the iteration count. `alg` and `enc` are set through their
  arguments, and no header may hold `zip`: zujose does not compress.

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

Key management is `dir`, `A128KW`, `A192KW`, `A256KW`, `A128GCMKW`,
`A192GCMKW`, `A256GCMKW`, one of the `PBES2-*` algorithms, or `RSA-OAEP`
or `RSA-OAEP-256` to an RSA public key of at least 2048 bits, or
`ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW` or `ECDH-ES+A256KW` to an
EC key on P-256, P-384 or P-521 or an X25519 key. ECDH-ES generates a
fresh ephemeral key, written as `epk`, and takes `apu` and `apv` from
`header`; in direct mode (`ECDH-ES`) it encrypts to one recipient.
`RSA1_5` is refused: it is accepted by
[`jwe_decrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_decrypt.md)
only, when `algorithms` names it, and it never encrypts. Content
encryption is `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`,
`A128GCM`, `A192GCM` or `A256GCM`. `A*GCMKW` writes the key wrapping
`iv` and `tag` into the header, and `PBES2-*` writes a random 16-byte
`p2s`; none of the three can be given.

For `PBES2-*` the key is the password, as an `oct` key:
`jwk_oct(charToRaw(enc2utf8(password)))`. The iteration count is `p2c`
in `header`, a whole number of at least 1000, and defaults to 600 000. A
recipient decrypting with
[`jwe_decrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_decrypt.md)
accepts at most `jose_limits()$p2c` iterations, by default also 600 000.
Other implementations cap `p2c` lower when they decrypt: Python's
jwcrypto at 16 384 and JavaScript's `jose` at 10 000 by default. A token
for them needs `header = list(p2c = 10000)` or less, as in the example;
the default stays high because the iteration count is a
password-protected token's only defence against offline guessing.

## See also

[`jwe_decrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_decrypt.md).

## Examples

``` r
key <- jwk_generate("oct", alg = "A128KW", kid = "kek")
token <- jwe_encrypt("secret", key)
token
#> [1] "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoia2VrIn0.NyNO276htSjtRphwrl_xrpiNK0P5cT_e6I7CCjzNCxDdkwb1wZyw_w.gSGSDXB4zdQBOf_eKfLJuw.omp52lE6iP5tB5sVLW7Vqw.zIpSKkS1gEwBcMSUrF8iBA"
jwe_decrypt(token, key, algorithms = "A128KW", encryptions = "A128CBC-HS256")
#> <jwe_decrypted> A128KW with A128CBC-HS256, key "kek"
#> Header:
#>   alg: "A128KW"
#>   enc: "A128CBC-HS256"
#>   kid: "kek"
#> Plaintext: 6 bytes

# AES-GCM content encryption, under a password. A p2c of 10000 is one
# that jwcrypto and JavaScript's jose also read.
password <- jwk_oct(charToRaw("correct horse battery staple"))
token <- jwe_encrypt(
  "secret",
  password,
  alg = "PBES2-HS256+A128KW",
  enc = "A256GCM",
  header = list(p2c = 10000)
)
jwe_decrypt(
  token,
  password,
  algorithms = "PBES2-HS256+A128KW",
  encryptions = "A256GCM"
)$plaintext
#> [1] 73 65 63 72 65 74
```
