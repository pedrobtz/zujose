# RSA, EC and X25519 keys are usable, and Ed25519 keys are kept

    Code
      print(ed)
    Output
      <jose_key> OKP
        kid "ed"
        ! not usable: zujose has no Ed25519

# printing a key never shows its secret

    Code
      print(key)
    Output
      <jose_key> oct, 256 bits
        kid "k1"
        private: yes (not shown)

