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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6+ldr9ZTNFawLdZExLNF
#> U9pFmzzjMUeUUD7MKp/+cJ9bbVuRKC+6lZih3QFM1at3ExW/WB/PeTlyxj79IZHG
#> cCFiDIke/Drb3y2kMliV8J4UZFytUQvmqDLQNdSfMTUqKrBPzeuRHOWKSCx3+i6e
#> lFCmc+mMQZZba8kp0RjL9UxjXURJPrqxRAG+ZrPljItiIV0X30m5Gw9hktFKyrxn
#> +ybwbLGpRZOY4byS/NQsrABAwetnVMt3TKsyYE/0N3q8m69ln+4wlfIQd1RmQQqe
#> USahCFRElURch6DniupOdJiVTgff8ipAuuP67D0YgEVAIRVO+PIn58hUJWAFDMT5
#> 0wIDAQAB
#> -----END PUBLIC KEY-----
```
