# Package index

## JSON Web Tokens

- [`jwt_encode()`](https://pedrobtz.github.io/zujose/reference/jwt_encode.md)
  : Encode a JWT
- [`jwt_decode()`](https://pedrobtz.github.io/zujose/reference/jwt_decode.md)
  : Check a JWT and return its claims
- [`jwt_decoder()`](https://pedrobtz.github.io/zujose/reference/jwt_decoder.md)
  : A reusable JWT check

## Signatures (JWS)

- [`jws_sign()`](https://pedrobtz.github.io/zujose/reference/jws_sign.md)
  : Sign a payload as a JWS
- [`jws_signer()`](https://pedrobtz.github.io/zujose/reference/jws_signer.md)
  : One signer of a multi-signature JWS
- [`jws_verify()`](https://pedrobtz.github.io/zujose/reference/jws_verify.md)
  : Verify a JWS

## Encryption (JWE)

- [`jwe_encrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_encrypt.md)
  : Encrypt a payload as a JWE
- [`jwe_recipient()`](https://pedrobtz.github.io/zujose/reference/jwe_recipient.md)
  : One recipient of a multi-recipient JWE
- [`jwe_decrypt()`](https://pedrobtz.github.io/zujose/reference/jwe_decrypt.md)
  : Decrypt a JWE
- [`jwe_decryption()`](https://pedrobtz.github.io/zujose/reference/jwe_decryption.md)
  : Accept an encrypted JWT

## Keys and key sets

- [`jwk_oct()`](https://pedrobtz.github.io/zujose/reference/jwk_oct.md)
  : Make a symmetric key
- [`jwk_generate()`](https://pedrobtz.github.io/zujose/reference/jwk_generate.md)
  : Generate a random key
- [`as_jwk()`](https://pedrobtz.github.io/zujose/reference/as_jwk.md) :
  Read a JSON Web Key
- [`jwk_set()`](https://pedrobtz.github.io/zujose/reference/jwk_set.md)
  [`as_jwk_set()`](https://pedrobtz.github.io/zujose/reference/jwk_set.md)
  : Key sets
- [`jwk_public()`](https://pedrobtz.github.io/zujose/reference/jwk_public.md)
  : The public part of a key or key set
- [`jwk_json()`](https://pedrobtz.github.io/zujose/reference/jwk_json.md)
  : Write a key or key set as JSON
- [`jwk_pem()`](https://pedrobtz.github.io/zujose/reference/jwk_pem.md)
  : Write a key as PEM
- [`jwk_with_kid()`](https://pedrobtz.github.io/zujose/reference/jwk_with_kid.md)
  : Set a key's identifier
- [`jwk_thumbprint()`](https://pedrobtz.github.io/zujose/reference/jwk_thumbprint.md)
  : JWK thumbprint

## Inspection, limits and errors

- [`jose_peek()`](https://pedrobtz.github.io/zujose/reference/jose_peek.md)
  : Look inside a token without verifying it
- [`jose_limits()`](https://pedrobtz.github.io/zujose/reference/jose_limits.md)
  : Resource limits for untrusted tokens
- [`zujose_info()`](https://pedrobtz.github.io/zujose/reference/zujose_info.md)
  : Algorithms available in this installation
- [`zujose_error`](https://pedrobtz.github.io/zujose/reference/zujose_error.md)
  : Conditions raised by zujose
