# printing claims shows times in UTC

    Code
      print(jwt_decode(jwt, key, "HS256", now = as_posixct(1.8e+09)))
    Output
      <jwt_claims> verified HS256, key "k"
        sub: "u1"
        exp: 2027-01-15 08:01:00 UTC
        iat: 2027-01-15 08:00:00 UTC

