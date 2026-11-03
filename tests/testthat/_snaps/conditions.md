# argument errors say which argument is wrong

    Code
      jws_sign("x", key, format = "compact", unprotected = list(a = 1))
    Condition
      Error:
      ! The compact serialization has no unprotected header.
    Code
      jwe_encrypt("x", kek, "A128KW", header = list(epk = list()))
    Condition
      Error:
      ! `epk` is generated for each message; it cannot be given.
    Code
      jwt_decode(jwt_encode(list(), key), key, "HS256", leeway = "a")
    Condition
      Error:
      ! `leeway` must be a number of seconds, at least 0.
    Code
      jose_limits(token = 0)
    Condition
      Error:
      ! `token` must be a whole number of at least 1, or Inf.
    Code
      jwk_thumbprint(key, uri = NA)
    Condition
      Error in `jwk_thumbprint()`:
      ! `uri` must be TRUE or FALSE.

# unsupported algorithms name the zucrypt version they need

    Code
      conditionMessage(err)
    Output
      [1] "Algorithm \"RS256\" needs zucrypt (>= 0.4.0)."

# a bad format or require is an argument error

    Code
      jws_sign("x", key, format = "bogus")
    Condition
      Error in `jws_sign()`:
      ! `format` must be one of "compact", "flattened", "general".

