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
#> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA08IC95Wgyry5hrS/7Vlu
#> IWC5qSzDic4pipzl7f3gwhoUalVE5HFjYzCBXBQzjAI8BxsuTkpaxqIIZLrIJb1h
#> QQBTxNcAQU3L2tExnOshQ8s8cAXrR18ZSzjL2uxPVZFNu8rMLKIEDXi2Duh7RQue
#> tFceaC3v8cOUvtwayDVW0D/LBk5Z80cLRn1A4zYjVemJmb/7FuAOkHzDa68cEmnh
#> j5KK25rlFRcN8Gm6/0/i4rEJkrJ9cyqQFGKwfZcZ8klYqGGBzvk78eHp3doy41F9
#> 85CvxZtzP8Z1UEXpcD8WgTMb42BZsu0BCD/mfHHta3Pnh15gfHTXhfG0YWFSUjkY
#> hwIDAQAB
#> -----END PUBLIC KEY-----
```
