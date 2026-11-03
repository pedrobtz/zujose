# a refused oct size has a message

    Code
      jwk_generate("oct", size = 120)
    Condition
      Error in `jwk_generate()`:
      ! `size` must be a whole number of bytes, in bits, of at least 128.

---

    Code
      jwk_generate("oct", size = 128, alg = "HS256")
    Condition
      Error in `jwk_generate()`:
      ! An HS256 key must be at least 256 bits.

# printing a key never shows its secret

    Code
      print(key)
    Output
      <jwk> oct, 256 bits
        kid "k1"
        private: yes (not shown)

# RSA, EC and X25519 keys are usable, and Ed25519 keys are kept

    Code
      print(ed)
    Output
      <jwk> OKP
        kid "ed"
        ! not usable: zujose has no Ed25519

