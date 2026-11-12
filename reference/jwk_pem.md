# Write a key as PEM

`jwk_pem()` writes an RSA, EC or X25519 key as PEM: the public key as
SubjectPublicKeyInfo (`PUBLIC KEY`), or with `private = TRUE` the
private key as PKCS#8 (`PRIVATE KEY`), byte for byte as OpenSSL writes
them.

## Usage

``` r
jwk_pem(key, private = FALSE)
```

## Arguments

- key:

  An RSA, EC or X25519 `jwk`.

- private:

  Whether to write the private key.

## Value

A single string.

## Secrets in memory

zujose is pure R, and so are its keys: an `oct` secret, and the private
members of an RSA, EC or X25519 key, are ordinary R vectors. R copies
vectors freely and has no way to wipe one, so a secret may stay in
memory after the key is gone, and may reach a saved workspace or a core
dump. zujose never prints secret members and never puts them in an error
message, but it cannot do more than that. Keep long-lived secrets out of
saved workspaces (`.RData`) and load them from a secret store when they
are needed.

## See also

[`as_jwk()`](https://pedrobtz.github.io/zujose/reference/as_jwk.md),
which reads PEM.

## Examples

``` r
key <- jwk_generate("RSA")
cat(jwk_pem(key))
#> -----BEGIN PUBLIC KEY-----
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8H2iGnHFeLmDYptrYO5X
#> fwE4AacHEGp/FyA5azlW5ORvYUklhEiN1yJvuf7o5gMQxJ0ccOoMixvjpjT6Vxgo
#> 4+7kPzK3EI3EyVRAlrNHfS53Tf74zuOe/3mtRanPG87j0qVbOgk9x/JAf0SSxR//
#> GstxMCzG8+tgC+MW9vwDTC67mnTZ6xwX72VVvxSCK+KNdkErSu2tEj6+7Z6Q0m/i
#> mhfT5fCjlHJo6gZ8nBfgtVAC2ZRjEv1mWkDzIAlpIdd5PahVrL3q+158ddqR+5Cn
#> IAqCZ6hzhl5VYjuj8f8j9syXITQzCC5Sv++rmv0CHTCwGq2wnL/U2xpiRYeKgH8g
#> 0QIDAQAB
#> -----END PUBLIC KEY-----
```
