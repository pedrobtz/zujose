# Decrypt a JWE

`jose_decrypt()` decrypts a JWE in any serialization. The caller names
the key management algorithms and the content encryption algorithms it
accepts; neither has a default. A token with `zip` is refused (RFC 8725
section 3.6).

## Usage

``` r
jose_decrypt(token, key, algorithms, encryptions, limits = jose_limits())
```

## Arguments

- token:

  The JWE: a compact serialization, or JSON text.

- key:

  A `jose_key`, a `jose_keyset`, or a function of the header returning
  one.

- algorithms:

  The key management algorithms to accept, such as `"A256KW"`.

- encryptions:

  The content encryption algorithms to accept, such as
  `"A256CBC-HS512"`.

- limits:

  Resource limits, from
  [`jose_limits()`](https://pedrobtz.github.io/zujose/reference/jose_limits.md).

## Value

A list of class `jose_decrypted` with `plaintext` (raw), `header` (the
protected, shared and per-recipient headers merged), `protected`, and
the `kid`, `alg` and `enc` that decrypted it.

## Details

`RSA1_5` is decrypted only when `algorithms` names it. It is exposed to
Bleichenbacher-style attacks (RFC 8725 section 3.2); a padding failure
is replaced by a random content key, as RFC 7516 section 11.5 asks, so
that it fails exactly as a wrong key does. Prefer `RSA-OAEP-256`.

Every failure after the header checks (a wrong key, a bad tag, bad
padding, a failed key unwrap, a wrong length) raises the same
`zujose_decrypt_error` with the same message, so that the error cannot
tell an attacker which step failed (RFC 7516 section 11.5).

With several recipients, those whose algorithm is not in `algorithms`,
or for whom `key` holds no key, are skipped; decryption succeeds with
the first recipient it can decrypt for.

## Examples

``` r
# RFC 7516 Appendix A.3.
token <- paste0(
  "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.",
  "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.",
  "AxY8DCtDaGlsbGljb3RoZQ.",
  "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.",
  "U0m_YmjN04DJvceFICbCVQ"
)
key <- as_jose_key('{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}')
out <- jose_decrypt(token, key, "A128KW", "A128CBC-HS256")
rawToChar(out$plaintext)
#> [1] "Live long and prosper."
```
