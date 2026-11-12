source("pre.R")
kw <- jwk_generate("oct", alg = "A128KW", kid = "kw"); gk <- jwk_generate("oct", alg = "A256GCMKW", kid = "gk"); gk2 <- jwk_generate("oct", alg = "A256GCMKW", kid = "gk2")
rsa <- jwk_generate("RSA", kid = "rsa"); e1 <- jwk_generate("EC", crv = "P-384", kid = "e1"); e2 <- jwk_generate("EC", crv = "P-384", kid = "e2"); x <- jwk_generate("OKP", kid = "x")
pw <- jwk_oct(charToRaw("password"), kid = "pw")
keys <- list(kw, gk, gk2, rsa, e1, e2, x, pw)
rec <- list(jwe_recipient(kw, "A128KW"), jwe_recipient(gk, "A256GCMKW", header = list(note = "hi")), jwe_recipient(gk2, "A256GCMKW"),
  jwe_recipient(jwk_public(rsa), "RSA-OAEP-256"), jwe_recipient(jwk_public(e1), "ECDH-ES+A256KW", header = list(apu = "QQ", apv = "Qg")), jwe_recipient(jwk_public(e2), "ECDH-ES+A128KW"),
  jwe_recipient(jwk_public(x), "ECDH-ES+A192KW"), jwe_recipient(pw, "PBES2-HS384+A192KW", header = list(p2c = 1500)))
for (enc in c("A256CBC-HS512", "A192GCM")) for (i in 1:3) {
  tok <- jwe_encrypt("multi-secret", rec, enc = enc, header = list(cty = "text"), unprotected = list(jku = "x"), aad = "extra", format = "general")
  for (k in keys) { d <- try_(jwe_decrypt(tok, k, c("A128KW","A256GCMKW","RSA-OAEP-256","ECDH-ES+A256KW","ECDH-ES+A128KW","ECDH-ES+A192KW","PBES2-HS384+A192KW"), enc)); if (inherits(d, "err")) cat("SELF FAIL", k$kid, d$msg, "\n") }
  add(name = paste("multi", enc, i), token = tok, keys = lapply(keys, jwk_json, private = TRUE), pt = "multi-secret", enc = enc)
}
cat(substr(OUT[[1]]$token, 1, 1500), "\n")
# apu/apv placements, single recipient
ec <- jwk_generate("EC", crv = "P-256", kid = "p")
A <- function(name, ...) { r <- try_(jwe_encrypt("apu-test", ...)); if (inherits(r, "err")) cat(name, "ERR", r$cls[1], r$msg, "\n") else { d <- try_(jwe_decrypt(r, ec, c("ECDH-ES", "ECDH-ES+A128KW"), c("A128GCM", "A192CBC-HS384"))); if (inherits(d, "err")) cat(name, "SELF FAIL", d$msg, "\n"); add(name = name, token = r, keys = list(jwk_json(ec, TRUE)), pt = "apu-test") } }
A("apu unprotected flat", jwk_public(ec), "ECDH-ES", "A192CBC-HS384", unprotected = list(apu = "QWxpY2U", apv = "Qm9i"), format = "flattened")
A("apu unprotected general", jwk_public(ec), "ECDH-ES+A128KW", "A128GCM", unprotected = list(apu = "QWxpY2U"), format = "general")
A("apu recipient flat", list(jwe_recipient(jwk_public(ec), "ECDH-ES", header = list(apu = "QWxpY2U", apv = "Qm9i"))), enc = "A128GCM", format = "flattened")
A("apu split", list(jwe_recipient(jwk_public(ec), "ECDH-ES", header = list(apv = "Qm9i"))), enc = "A128GCM", header = list(apu = "QWxpY2U"), format = "general")
A("apu empty string", jwk_public(ec), "ECDH-ES", "A128GCM", header = list(apu = "", apv = ""))
A("apu long", jwk_public(ec), "ECDH-ES", "A128GCM", header = list(apu = zujose:::b64url_encode(as.raw(sample(0:255, 300, TRUE)))))
A("apu bad b64", jwk_public(ec), "ECDH-ES", "A128GCM", header = list(apu = "QWxpY2U="))
A("apu num", jwk_public(ec), "ECDH-ES", "A128GCM", header = list(apu = 5))
A("apu on A128KW", jwk_generate("oct", alg = "A128KW"), "A128KW", "A128GCM", header = list(apu = "QQ"))
A("epk given", jwk_public(ec), "ECDH-ES", "A128GCM", header = list(epk = list(kty = "EC")))
A("ECDH general 1 recipient", jwk_public(ec), "ECDH-ES", "A128GCM", format = "general")
A("ECDH with private key as recipient", ec, "ECDH-ES", "A128GCM")
flush_out("p08.json")
