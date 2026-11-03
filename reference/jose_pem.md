# Write a key as PEM

`jose_pem()` writes an RSA, EC or X25519 key as PEM: the public key as
SubjectPublicKeyInfo (`PUBLIC KEY`), or with `private = TRUE` the
private key as PKCS#8 (`PRIVATE KEY`), byte for byte as OpenSSL writes
them.

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

[`as_jose_key()`](https://pedrobtz.github.io/zujose/reference/as_jose_key.md),
which reads PEM.

## Examples

``` r
key <- jose_key_generate("RSA")
cat(jose_pem(key))
#> -----BEGIN PUBLIC KEY-----
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnnmeDLmnUiMZUsIOE+gg
#> WSJuqpucaZadvpL1m852FizbDapdUKCj+AsuD3caTUG60xVwlLed5SeGxAkvlEkW
#> HU2SlwsC1R4HSnilqoXRIrFyc3X5MIXMJ5QPwvPetje7WRX3xe7ITyLlK+5FULY4
#> EBlLCGbZe58YsCkA2W8jtcRNXbvkTQteHkP86gPXYP5zkQmh6/2v8Y9jBZmlC9Po
#> vgGACPa/2uKOFUyz7YEKZ4sCJQDianjZmDO3Q79Z06nrUWZVlWGdMvdhjwF02k+2
#> XlXD7KwH5GF6kGRu9RzhizDey4b6j8eH4xCEWdNHNH8ndZ0pZH+ajtKtwFHMfVl8
#> 9wIDAQAB
#> -----END PUBLIC KEY-----
```
