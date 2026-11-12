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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt8bckh8RpLzQsNj9IukL
#> oInqFZ89Igrw+CiyUb+GoMcDt+1H9eCvxBn8mR35unFsGtHebAqq70CGzoE5OfSA
#> b4t34UK+RyEGIPtMn3LfwAJZV+QxidZwyjs1t7QV9vjCCSH3DG/OqSZWzEAqfSBS
#> 5KRhIczucwrBTT59QZkOgY6a/r69X1IhrhOg9hHH428k3sv5zgSeT0ODKYEjI+SS
#> UccIwVFDvdKMsr58KL+A8zR5DQi/xUt65S4lN8dbOorbZ5O1luLLqEI65EdPQDm2
#> iFtySBgBiDbm771zVb1m0zzYHCsi/yFEhQ7z4QhUf0Vw0YFd368xi5PESOu7tTSj
#> mwIDAQAB
#> -----END PUBLIC KEY-----
```
