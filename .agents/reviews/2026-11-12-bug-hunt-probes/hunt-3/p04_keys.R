source("pre.R")
emit <- function(name, k) {
  priv <- k$kty == "oct" || zujose:::has_private(k)
  add(name = name, kty = k$kty,
      json_priv = if (priv) jwk_json(k, private = TRUE) else "",
      json_pub = if (k$kty == "oct") "" else jwk_json(k),
      pem_priv = if (k$kty != "oct" && priv) jwk_pem(k, private = TRUE) else "",
      pem_pub = if (k$kty != "oct") jwk_pem(k) else "",
      tp256 = jwk_thumbprint(k), tp384 = jwk_thumbprint(k, "sha384"), tp512 = jwk_thumbprint(k, "sha512"),
      tp_pub = if (k$kty != "oct") jwk_thumbprint(jwk_public(k)) else "",
      uri = jwk_thumbprint(k, uri = TRUE), kid_auto = jwk_with_kid(k)$kid)
}
for (i in 1:250) for (crv in c("P-256", "P-384", "P-521")) emit(paste("EC", crv, i), jwk_generate("EC", crv = crv, kid = "é", use = "sig", alg = c(`P-256`="ES256",`P-384`="ES384",`P-521`="ES512")[[crv]]))
for (i in 1:300) emit(paste("OKP", i), jwk_generate("OKP", crv = "X25519"))
for (s in c(2048, 2048, 2048, 2049, 2056, 3072, 4096)) { k <- try_(jwk_generate("RSA", size = s, key_ops = c("sign", "verify"))); if (inherits(k, "err")) cat("RSA", s, k$msg, "\n") else emit(paste("RSA", s), k) }
for (n in c(16, 17, 32, 48, 64, 100)) emit(paste("oct", n), jwk_oct(as.raw(sample(0:255, n, TRUE))))
emit("oct zeros", jwk_oct(raw(32)))
emit("oct gen", jwk_generate("oct", alg = "HS512", kid = "h", use = "sig"))
flush_out("p04.json"); cat(length(OUT), "\n")
