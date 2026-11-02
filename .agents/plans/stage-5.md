# Stage 5 plan (scratch)

1. R/aes.R: one-block AES over the _nopad CBC pair, RFC 3394 key wrap,
   AES_CBC_HMAC_SHA2. Test against RFC 3394 4.1-4.6 and RFC 7518 B.
2. R/jwe.R: encrypt_jwe() (CEK/IV injectable), jose_encrypt(),
   jose_recipient(), jose_decrypt(), jose_decryption(). zip refused; one
   decrypt error (D5).
3. jose_jwt_decode(decrypt = ): D12.
4. Tests: RFC 7516 A.3 and A.4, RFC 7520 5.9 and 5.8, uniform failures.
