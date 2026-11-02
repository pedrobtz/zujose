# printing a verified JWS shows the header, not the payload

    Code
      print(jose_verify(jose_sign("secret text", key, "HS256"), key, "HS256"))
    Output
      <jose_verified> HS256, key "k"
      Header:
        alg: "HS256"
        kid: "k"
      Payload: 11 bytes

