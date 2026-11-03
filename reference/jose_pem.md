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

[`as_jose_key()`](https://pedrobtz.github.io/zujwt/reference/as_jose_key.md),
which reads PEM.

## Examples

``` r
key <- jose_key_generate("RSA")
cat(jose_pem(key))
#> -----BEGIN PUBLIC KEY-----
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyGxTfNudK7Aikpgoigzc
#> aIUMcgsXsGdbHsa6117jeSEJ/IpF/OMTRFKMhkTCSue5I43QGYxhWfu/tjUF1MIW
#> NVlvR7mOP2w8SGVvW7F2oK55PbhdS+Kigrugi1Jm+YMjb5kpbQDt6Z4UEx4ue/Tw
#> ewBbI+RLgIKLAipjNFDacaaFT+axbetJyRSV6YCypCALXOSsBZ0x/AJISM+llzQP
#> gabWaCW0c6I5UJNGb67sxe6vE8fUrLkBhRTZGks9E/Bx73I7vWyukL1+a787QvX/
#> gmdkghJN9lK8Y6TBcvWrvA+WBjvJc+J1lq9sDp8e0DpFrsRhHWYdm7BXnhI7aPcE
#> mwIDAQAB
#> -----END PUBLIC KEY-----
```
