# Conditions raised by zujose

Every error zujose raises inherits from `zujose_error`, then `error` and
`condition`, so a caller can catch all of them, or one kind, with
[`tryCatch()`](https://rdrr.io/r/base/conditions.html). Match on the
class, never on the message.

## Details

|  |  |  |
|----|----|----|
| Class | Fields | Raised when |
| `zujose_argument_error` |  | an argument is of the wrong type, out of range, or inconsistent with another, such as `format = "compact"` with several recipients |
| `zujose_parse_error` |  | a token, header or key is not well formed, or is over a limit |
| `zujose_policy_error` |  | an algorithm is not allowed, a `crit` header is not understood, or a key does not fit the algorithm |
| `zujose_key_error` |  | a key is missing, malformed or too weak |
| `zujose_signature_error` |  | a signature or MAC does not verify |
| `zujose_decrypt_error` |  | decryption fails, for any reason, after the header has passed the policy checks |
| `zujose_claim_error` | `claim` | a JWT claim is missing or does not match what the caller expects |
| `zujose_expired_error` | `claim`, `time`, `now` | the token has expired, or is older than `max_age` |
| `zujose_not_yet_valid_error` | `claim`, `time`, `now` | the token is not valid yet, or was issued in the future |
| `zujose_audience_error` | `claim` | the token is not for this audience |
| `zujose_issuer_error` | `claim` | the token is not from this issuer |
| `zujose_subject_error` | `claim` | the token is not about this subject |
| `zujose_missing_claim_error` | `claim` | a required claim is absent |
| `zujose_unsupported_error` | `algorithm`, `needs` | an algorithm needs a newer `zucrypt` than the one installed |

The last six inherit from `zujose_claim_error`, so a caller can catch
every claim failure at once or one cause.

Every decryption failure raises the same class with the same message, so
that the error cannot tell an attacker which step failed (RFC 7516
section 11.5). Messages never contain key material, decrypted bytes or
token text.

## Examples

``` r
key <- jwk_generate("oct", alg = "HS256")
jwt <- jwt_encode(list(sub = "user-1"), key, expires_in = -120)

# Catch one kind of failure by its class.
tryCatch(
  jwt_decode(jwt, key, algorithms = "HS256"),
  zujose_expired_error = function(e) {
    paste("expired at", format(e$time, tz = "UTC"))
  }
)
#> [1] "expired at 2026-11-03 16:07:29"
```
