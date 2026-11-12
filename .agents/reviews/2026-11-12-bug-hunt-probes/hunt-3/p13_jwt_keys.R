source("pre.R")
rsa <- jwk_generate("RSA", kid = "rsa-k")
crv <- c(ES256 = "P-256", ES384 = "P-384", ES512 = "P-521")
for (a in c("HS256","HS384","HS512","RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES384","ES512")) {
  k <- if (startsWith(a, "HS")) jwk_generate("oct", alg = a, kid = "h") else if (startsWith(a, "ES")) jwk_generate("EC", crv = crv[[a]], kid = "é-kid") else rsa
  tok <- jwt_encode(list(iss = "zujose", sub = "u1", aud = c("a", "b"), n = 42L), k, a, expires_in = 3600, not_before = -5, jti = TRUE)
  cl <- jwt_decode(tok, k, a, audience = "a", issuer = "zujose")
  add(alg = a, token = tok, pem = if (k$kty == "oct") "" else jwk_pem(k), secret = if (k$kty == "oct") hexs(k$k) else "", kid = k$kid, now = zujose:::jwt_now())
  # nested: sign then encrypt
  ek <- jwk_generate("EC", crv = "P-256", kid = "enc")
  nested <- jwe_encrypt(tok, jwk_public(ek), "ECDH-ES+A128KW", "A128GCM", header = list(cty = "JWT"))
  cl2 <- try_(jwt_decode(nested, k, a, audience = "a", issuer = "zujose", decrypt = jwe_decryption(ek, "ECDH-ES+A128KW", "A128GCM")))
  if (inherits(cl2, "err")) cat("nested self-decode FAIL", a, cl2$msg, "\n")
  add(alg = paste0("nested-", a), token = nested, inner_alg = a, pem = if (k$kty == "oct") "" else jwk_pem(k), secret = if (k$kty == "oct") hexs(k$k) else "", kid = k$kid, enc_key = jwk_json(ek, TRUE), sig_key = jwk_json(k, TRUE), now = zujose:::jwt_now())
}
# symmetric encrypted-only JWT
d <- jwk_generate("oct", size = 256, kid = "dir")
claims <- zujson::json_write(list(iss = "zujose", exp = zujose:::jwt_now() + 600))
enc_only <- jwe_encrypt(claims, d, "dir", "A256GCM", header = list(typ = "JWT"))
add(alg = "enc-only", token = enc_only, enc_key = jwk_json(d, TRUE))
cl <- try_(jwt_decode(enc_only, d, "HS256", issuer = "zujose", decrypt = jwe_decryption(d, "dir", "A256GCM"))); cat("enc-only self-decode:", if (inherits(cl, "err")) cl$msg else "ok", "\n")
flush_out("p13.json")
