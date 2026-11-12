source("helper.R")
d <- zujson::json_parse(paste(readLines("data/jwe.json", warn = FALSE), collapse = "\n"), simplify = "none"); t <- d$tok; K <- lapply(d$keys, as_jwk)
s <- zujson::json_parse(paste(readLines("data/sig.json", warn = FALSE), collapse = "\n"), simplify = "none")
ALG <- zujose_info(); KM <- ALG$algorithm[ALG$kind == "key management"]; CE <- ALG$algorithm[ALG$kind == "content encryption"]
sp <- function(tok) strsplit(paste0(tok, "."), ".", fixed = TRUE)[[1]]
cat("--- same JWS, three serializations\n")
rsa <- as_jwk(s$rsa_pub_spki); ec <- as_jwk(s[["ec_P-256_pub"]])
for (n in c("RS256", "PS384", "ES256")) { p <- sp(s$tokens[[n]]); key <- if (n == "ES256") ec else rsa
  a <- jws_verify(s$tokens[[n]], key, n); b <- jws_verify(sprintf('{"signature":"%s","payload":"%s","protected":"%s"}', p[3], p[2], p[1]), key, n)
  g <- jws_verify(sprintf('{"signatures":[{"signature":"%s","protected":"%s"}],"payload":"%s"}', p[3], p[1], p[2]), key, n)
  cat(n, identical(a$payload, b$payload), identical(a$payload, g$payload), identical(a$header, b$header), identical(a$header, g$header), identical(a$protected, g$protected), "\n") }
cat("--- same JWE, three serializations\n")
for (n in c("kw", "oaep", "ecdh_p256", "pbes2", "dir_cbc", "gcmkw", "ecdhkw_x25519")) { p <- sp(t[[n]]); key <- K[[c(kw = "oct16", oaep = "rsa", ecdh_p256 = "p256", pbes2 = "pw", dir_cbc = "oct32", gcmkw = "oct32", ecdhkw_x25519 = "x25519")[[n]]]]
  a <- jwe_decrypt(t[[n]], key, KM, CE)
  ek <- if (nzchar(p[2])) sprintf('"encrypted_key":"%s",', p[2]) else ""
  b <- jwe_decrypt(sprintf('{%s"tag":"%s","ciphertext":"%s","iv":"%s","protected":"%s"}', ek, p[5], p[4], p[3], p[1]), key, KM, CE)
  g <- jwe_decrypt(sprintf('{"recipients":[{%s"header":{}}],"tag":"%s","ciphertext":"%s","iv":"%s","protected":"%s"}', ek, p[5], p[4], p[3], p[1]), key, KM, CE)
  cat(n, identical(a$plaintext, b$plaintext), identical(a$plaintext, g$plaintext), identical(a$header, b$header), identical(a$header, g$header), "\n") }
cat("--- misc\n")
key <- jwk_oct(K32)
try_("alg + escaped alg dup", jws_verify(hs('{"alg":"HS256","\\u0061lg":"none"}', "x", K32), key, "HS256"))
try_("ALG upper only", jws_verify(hs('{"ALG":"HS256"}', "x", K32), key, "HS256"))
try_("compact empty protected", jws_verify("..", key, "HS256")); try_("compact protected {}", jws_verify(paste0(b64("{}"), ".e30."), key, "HS256")); try_("empty token", jws_verify("", key, "HS256")); try_("just dots 5", jwe_decrypt("....", key, "dir", "A256GCM"))
try_("jws_verify on jwe", jws_verify(t$dir_gcm, key, "HS256")); try_("jwe_decrypt on jws", jwe_decrypt(s$tokens$RS256, key, "dir", "A256GCM"))
# gcmkw header variants
p <- sp(t$gcmkw); h <- zujson::json_parse(rawToChar(unb64(p[1])), simplify = "none")
mut <- function(f) { hh <- f(h); paste(c(b64(zujson::json_write(hh)), p[2:5]), collapse = ".") }
dec <- function(l, tok, k = K$oct32) try_(l, jwe_decrypt(tok, k, KM, CE))
dec("gcmkw re-serialized same header (AAD differs?)", mut(identity)); cat("   header bytes identical after rewrite:", identical(b64(zujson::json_write(h)), p[1]), "\n")
dec("gcmkw iv 11 bytes", mut(function(h) { h$iv <- b64(unb64(h$iv)[-1]); h })); dec("gcmkw tag 12 bytes", mut(function(h) { h$tag <- b64(unb64(h$tag)[1:12]); h })); dec("gcmkw no tag", mut(function(h) { h$tag <- NULL; h })); dec("gcmkw iv number", mut(function(h) { h$iv <- 5; h }))
dec("gcmkw tag flipped", mut(function(h) { x <- unb64(h$tag); x[1] <- xor(x[1], as.raw(1)); h$tag <- b64(x); h }))
# ECDH: set with two curves
ks <- jwk_set(K$p384, K$p256, K$x25519, K$p256b); r <- dec("ecdh set mixed curves", t$ecdh_p256, ks); r <- dec("ecdh x25519 from mixed set", t$ecdh_x25519, ks)
dec("ecdh p256 token with p384 key", t$ecdh_p256, K$p384); dec("ecdh p256 token with x25519 key", t$ecdh_p256, K$x25519); dec("ecdh x25519 token with p256 key", t$ecdh_x25519, K$p256)
dec("rsa-oaep w/ 1024 priv", t$oaep, as_jwk(s$rsa1024_priv)); dec("rsa-oaep w/ EC key", t$oaep, K$p256); dec("kw w/ rsa key", t$kw, K$rsa)
dec("oaep token, key set of 17 RSA? (limit)", t$oaep, do.call(jwk_set, rep(list(K$rsa), 17)))
# X25519 private JWK with bogus x: decrypts, and what does jwk_public say
xj <- zujson::json_parse(d$keys$x25519, simplify = "none"); good_x <- xj$x; xj$x <- b64(raw(32)); bad <- as_jwk(zujson::json_write(xj))
dec("x25519 key with x=0 decrypts", t$ecdh_x25519, bad); cat("   public exported x:", zujson::json_parse(jwk_json(jwk_public(bad)), simplify = "none")$x, " true x:", good_x, "\n")
xj$x <- "AA"; try_("x25519 priv, x 1 byte", as_jwk(zujson::json_write(xj))); xj$d <- NULL; try_("x25519 pub, x 1 byte", as_jwk(zujson::json_write(xj)))
