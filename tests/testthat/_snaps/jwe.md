# algorithms and encryptions have no default and are checked

    Code
      jwe_decrypt(v$token, v$key)
    Condition
      Error in `jwe_decrypt()`:
      ! argument "algorithms" is missing, with no default
    Code
      jwe_decrypt(v$token, v$key, "A128KW")
    Condition
      Error in `jwe_decrypt()`:
      ! argument "encryptions" is missing, with no default

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

# a truncated tag that is a prefix of the real one is refused

    Code
      cat(unique(messages))
    Output
      Decryption failed.

# a bad plaintext or aad is named in the error

    Code
      jwe_encrypt(1, key, "A128KW")
    Condition
      Error in `jwe_encrypt()`:
      ! `plaintext` must be a raw vector or a single string.
    Code
      jwe_encrypt("x", key, "A128KW", aad = 1, format = "flattened")
    Condition
      Error in `jwe_encrypt()`:
      ! `aad` must be a raw vector or a single string.

