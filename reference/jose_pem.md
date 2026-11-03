# Write a key as PEM

`jose_pem()` writes an RSA, EC or X25519 key as PEM: the public key as
SubjectPublicKeyInfo (`PUBLIC KEY`), or with `private = TRUE` the
private key as PKCS#8 (`PRIVATE KEY`), byte for byte as the openssl
package writes them.

## Usage

``` r
jose_pem(key, private = FALSE)
```

## Arguments

- key:

  An RSA, EC or X25519 `jose_key`.

- private:

  Whether to write the private key.

## Value

A single string.

## See also

[`as_jose_key()`](https://pedrobtz.github.io/zujose/reference/as_jose_key.md),
which reads PEM.

## Examples

``` r
key <- jose_key_generate("RSA")
cat(jose_pem(key))
#> -----BEGIN PUBLIC KEY-----
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuXRYKXfbZQDS6BOciRs/
#> 28bwC7xuUjlHrjX7xy+8wHsrlp5z0bMMeUV7iTT28HoCPYG87t80LVAE09odc0Cw
#> AkkDqQmI9154ImnMAyU6DRYwAknpltalgEmEc9aLhscIyMnNFiokud/q27NRVUwY
#> 8lJaZqFCg0qLTvQuRwL6dN1NsxfvJjzcbsF7UFseNX0H0LukuyCvE0VfAQz6Yv/s
#> C9jjbE91TGRHQEf6XmntfNbRVLbO8yimDsZn0rCK7gXgx27lASDEZeKyKqkoIS63
#> yS5He0yMZCGDe/6zTlBKWO4rBEgoU/E/HSvvjwBb6mwYam1VMe6WiGOWz2JRWSwV
#> rQIDAQAB
#> -----END PUBLIC KEY-----
```
