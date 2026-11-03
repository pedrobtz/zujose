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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwsSSBH7P2fHkvOgOFOMA
#> V7wTo1SOkbHTYqkT5Z6Sns+cVYuQpG9WoAMetqeZETHTfImgj+FzCfj6kymhZaQY
#> nBl4xB6mnkwPu2nDwV1iCtrZVDJ3awO8f6OtYKjncdrEbGQ+ecOPud/wOSe8UQfU
#> oT26yNvoTKe18KFmGRNT/z0HNd2fuXSrWLp+ecmHfFJd0h6DPSf4Nd76hsuHSnzw
#> EAia5GbNjzyOPypCskwHzFt5viTTfSQeOgdQ1KCT1U55CNpJ5oEZJdDot9p5KI3e
#> HzYhURVCEGNu1CiiQ7Oy23f6inOv+GlXQIF1kboG4Jo2GrVB00TkoVnSjCBUQAw5
#> ZwIDAQAB
#> -----END PUBLIC KEY-----
```
