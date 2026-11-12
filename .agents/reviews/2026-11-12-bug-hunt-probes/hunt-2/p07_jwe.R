source("helper.R")
d <- zujson::json_parse(paste(readLines("data/jwe.json", warn = FALSE), collapse = "\n"), simplify = "none")
K <- lapply(d$keys, as_jwk); t <- d$tok
ALG <- zujose_info(); KM <- ALG$algorithm[ALG$kind == "key management"]; CE <- ALG$algorithm[ALG$kind == "content encryption"]
dec <- function(label, tok, key, algorithms = KM, encryptions = CE, ...) {
  r <- try_(label, jwe_decrypt(tok, key, algorithms = algorithms, encryptions = encryptions, ...))
  if (inherits(r, "jwe_decrypted")) cat("     ->", r$alg, r$enc, "kid:", r$kid %||% "-", "pt:", substr(rawToChar(r$plaintext), 1, 30), "\n")
  invisible(r)
}
keyfor <- c(dir_gcm = "oct32", dir_cbc = "oct32", dir_cbc512 = "oct64", kw = "oct16", kw256 = "oct32", gcmkw = "oct32", pbes2 = "pw", pbes2_512 = "pw", oaep = "rsa", oaep256 = "rsa", rsa15 = "rsa",
  flat_aad = "oct16", flat_unprot = "oct16", flat_noprot = "oct16", flat_noprot_aad = "oct16", zip = "oct32")
for (n in names(keyfor)) dec(n, t[[n]], K[[keyfor[[n]]]])
for (c in c("p256", "p384", "p521", "x25519")) for (p in c("ecdh_", "ecdhkw_", "ecdh_apu_", "ecdh_cbc512_")) dec(paste0(p, c), t[[paste0(p, c)]], K[[c]])
ks <- jwk_set(K$oct16, K$rsa, K$p256)
dec("general3 set", t$general3, ks); dec("general3 oct16", t$general3, K$oct16); dec("general3 rsa", t$general3, K$rsa); dec("general3 p256", t$general3, K$p256)
dec("general3 only RSA-OAEP allowed, set", t$general3, ks, algorithms = "RSA-OAEP")
dec("general3 wrong key p384", t$general3, K$p384)
dec("general3 oct32 (no fit)", t$general3, K$oct32)
for (n in grep("^hm_", names(t), value = TRUE)) dec(n, t[[n]], K$oct32)
dec("rsa15 not allowed", t$rsa15, K$rsa, algorithms = setdiff(KM, "RSA1_5"))
