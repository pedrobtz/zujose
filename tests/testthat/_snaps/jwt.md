# a signed JWT inside a signed JWT is refused (#46)

    Code
      jwt_decode(outer, key, "HS256")
    Condition
      Error in `jwt_decode()`:
      ! A signed JWT must not carry another JWT (`cty: "JWT"`); only a JWE may.

# signature checks come first

    Code
      jwt_decode(jwt, key)
    Condition
      Error in `jwt_decode()`:
      ! argument "algorithms" is missing, with no default

# printing claims shows times in UTC

    Code
      print(jwt_decode(jwt, key, "HS256", now = as_posixct(1.8e+09)))
    Output
      <jwt_claims> verified HS256, key "k"
        sub: "u1"
        exp: 2027-01-15 08:01:00 UTC
        iat: 2027-01-15 08:00:00 UTC

