# Resource limits for untrusted tokens

Every function that reads a token checks it against these limits before
decoding anything, so a hostile token cannot make zujose allocate or
compute much more than an honest one would. The defaults are far above
what real tokens need.

## Usage

``` r
jose_limits(
  token = 2^21,
  header = 2^14,
  payload = 2^20,
  signatures = 16,
  recipients = 16,
  keys = 16,
  p2c = 6e+05
)
```

## Arguments

- token:

  Maximum length of a token, in bytes. This bounds the encoded form,
  which is about 4/3 of the payload, so the default of 2 MiB leaves room
  for a payload at the `payload` limit. Encoding functions do not check
  these limits.

- header:

  Maximum length of a decoded protected header, in bytes.

- payload:

  Maximum length of a payload or ciphertext, in bytes. This applies to
  detached and unencoded (`b64: false`) payloads too.

- signatures:

  Maximum number of signatures in a JWS JSON serialization.

- recipients:

  Maximum number of recipients in a JWE JSON serialization.

- keys:

  Maximum number of keys tried for one token.

- p2c:

  Maximum PBES2 iteration count a token may ask for.

## Value

A list of class `jose_limits`.

## Details

A token over a limit fails with `zujose_parse_error`, except for `keys`:
more fitting keys than `keys` is a property of the key set as much as of
the token, and fails with `zujose_key_error`. Give the keys a `kid`, or
narrow the set. Use `Inf` to switch a limit off.

## Examples

``` r
jose_limits()
#> <jose_limits>
#>   token      2,097,152
#>   header     16,384
#>   payload    1,048,576
#>   signatures 16
#>   recipients 16
#>   keys       16
#>   p2c        600,000
jose_limits(token = 8192, signatures = 1)
#> <jose_limits>
#>   token      8,192
#>   header     16,384
#>   payload    1,048,576
#>   signatures 1
#>   recipients 16
#>   keys       16
#>   p2c        600,000
```
