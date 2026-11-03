# printing shows the header, not the plaintext

    Code
      print(jwe_decrypt(v$token, v$key, "A128KW", "A128CBC-HS256"))
    Output
      <jwe_decrypted> A128KW with A128CBC-HS256
      Header:
        alg: "A128KW"
        enc: "A128CBC-HS256"
      Plaintext: 22 bytes

---

    Code
      print(jwe_decryption(v$key, "A128KW", "A128CBC-HS256"))
    Output
      <jwe_decryption> A128KW with A128CBC-HS256

