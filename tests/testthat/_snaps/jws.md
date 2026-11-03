# printing a verified JWS shows the header, not the payload

    Code
      print(jws_verify(jws_sign("secret text", key, "HS256"), key, "HS256"))
    Output
      <jws_verified> HS256, key "k"
      Header:
        alg: "HS256"
        kid: "k"
      Payload: 11 bytes

