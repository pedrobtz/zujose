# a JWE's algorithm is checked against decrypt first (#77)

    Code
      jwt_decode(foo, kek, "HS256", decrypt = decrypt)
    Condition
      Error in `jwt_decode()`:
      ! The token's key management is not in `decrypt$algorithms`.
    Code
      jwt_decode(wrong, kek, "HS256", decrypt = decrypt)
    Condition
      Error in `jwt_decode()`:
      ! The token's key management is not in `decrypt$algorithms`.

