source("pre.R")
for (spec in list(list("EC", "P-256", 1500), list("EC", "P-384", 300), list("OKP", "X25519", 600), list("EC", "P-521", 200))) {
  k <- jwk_generate(spec[[1]], crv = spec[[2]]); pub <- jwk_public(k); kj <- jwk_json(k, TRUE)
  for (i in seq_len(spec[[3]])) { alg <- if (i %% 2) "ECDH-ES" else "ECDH-ES+A128KW"; add(name = paste(spec[[2]], i), token = jwe_encrypt("zz", pub, alg, "A128GCM"), key = kj, pt = "7a7a", fmt = "compact") }
}
flush_out("p15.json")
set <- jwk_set(jwk_generate("EC", kid = "a", use = "sig"), jwk_generate("RSA", kid = "b", key_ops = c("sign", "verify")), jwk_generate("OKP", kid = "c"), jwk_oct(as.raw(1:32), kid = "d", alg = "HS256"))
writeLines(jwk_json(set), "p15_set_pub.json"); writeLines(jwk_json(set, TRUE), "p15_set_priv.json")
cat(length(set), length(jwk_public(set)), "\n")
