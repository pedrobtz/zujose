# printing says the token is not verified

    Code
      print(jose_peek(rfc7519_jwt()))
    Output
      <jose_unverified> JWS, compact serialization
      ! Not verified: nothing here can be trusted.
      Header:
        typ: "JWT"
        alg: "HS256"
      Claims:
        iss: "joe"
        exp: 1300819380
        http://example.com/is_root: true

---

    Code
      print(jose_peek(rfc7520_token(81)))
    Output
      <jose_unverified> JWE, compact serialization
      ! Not verified: nothing here can be trusted.
      Header:
        alg: "RSA1_5"
        kid: "frodo.baggins@hobbiton.example"
        enc: "A128CBC-HS256"

