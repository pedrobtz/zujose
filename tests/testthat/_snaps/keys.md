# printing a key never shows its secret

    Code
      print(key)
    Output
      <jose_key> oct, 256 bits
        kid "k1"
        private: yes (not shown)

# EC and OKP keys read but are marked not usable yet

    Code
      print(ec)
    Output
      <jose_key> EC
        kid "bilbo.baggins@hobbiton.example"
        use sig
        ! not usable yet: needs zucrypt (>= 0.5.0)

