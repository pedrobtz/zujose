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
      Signature: 32 bytes

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
      Encrypted key: 256 bytes
      IV: 16 bytes
      Ciphertext: 288 bytes
      Tag: 16 bytes

---

    Code
      print(jose_peek(rfc7520_token(183)))
    Output
      <jose_unverified> JWE, flattened serialization
      ! Not verified: nothing here can be trusted.
      Header:
        alg: "A128KW"
        kid: "81b20965-8332-43d9-a468-82160ad91ac8"
        enc: "A128GCM"
      Encrypted key: 24 bytes
      IV: 12 bytes
      Ciphertext: 273 bytes
      Tag: 16 bytes
      AAD: 183 bytes

