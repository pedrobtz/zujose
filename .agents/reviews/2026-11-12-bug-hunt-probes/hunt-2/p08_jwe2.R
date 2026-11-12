source("helper.R")
d <- zujson::json_parse(paste(readLines("data/jwe.json", warn = FALSE), collapse = "\n"), simplify = "none")
K <- lapply(d$keys, as_jwk); t <- d$tok
ALG <- zujose_info(); KM <- ALG$algorithm[ALG$kind == "key management"]; CE <- ALG$algorithm[ALG$kind == "content encryption"]
dec <- function(label, tok, key, algorithms = KM, encryptions = CE, ...) {
  r <- try_(label, jwe_decrypt(tok, key, algorithms = algorithms, encryptions = encryptions, ...))
  if (inherits(r, "jwe_decrypted")) cat("     ->", r$alg, r$enc, "kid:", r$kid %||% "-", "pt:", substr(rawToChar(r$plaintext), 1, 30), "\n")
  invisible(r)
}
sp <- function(tok) strsplit(paste0(tok, "."), ".", fixed = TRUE)[[1]]
jn <- function(p) paste(p, collapse = ".")
# GCM tag/iv truncation
p <- sp(t$hm_gcm); tag <- unb64(p[5])
for (n in c(15, 12, 8, 4, 1, 0)) dec(paste("gcm tag len", n), jn(c(p[1:4], b64(tag[seq_len(n)]))), K$oct32)
dec("gcm tag +1", jn(c(p[1:4], b64(c(tag, as.raw(0))))), K$oct32)
dec("gcm iv empty", jn(c(p[1:2], "", p[4:5])), K$oct32)
dec("gcm ct empty", jn(c(p[1:3], "", p[5])), K$oct32)
# gcmkw tag trunc inside header -> header changed => fails anyway; check class is parse (header-only) 
# error-class matrix (D5)
cls <- function(tok, key, ...) { e <- tryCatch(jwe_decrypt(tok, key, algorithms = KM, encryptions = CE, ...), error = function(e) e); if (!inherits(e, "error")) return("DECRYPTED"); paste(class(e)[1], "|", conditionMessage(e), "|", paste(setdiff(names(unclass(e)), c("message", "call")), collapse = ",")) }
flip <- function(tok, i, at = 3) { p <- sp(tok); r <- unb64(p[i]); r[at] <- xor(r[at], as.raw(1)); p[i] <- b64(r); jn(p) }
cat("--- oracle matrix\n")
for (n in c("dir_gcm", "dir_cbc", "kw", "gcmkw", "pbes2", "oaep", "oaep256", "rsa15", "ecdh_p256", "ecdhkw_p256", "ecdh_x25519", "ecdhkw_x25519")) {
  kn <- c(dir_gcm = "oct32", dir_cbc = "oct32", kw = "oct16", gcmkw = "oct32", pbes2 = "pw", oaep = "rsa", oaep256 = "rsa", rsa15 = "rsa", ecdh_p256 = "p256", ecdhkw_p256 = "p256", ecdh_x25519 = "x25519", ecdhkw_x25519 = "x25519")[[n]]
  tk <- t[[n]]; p <- sp(tk)
  res <- c(
    ek_flip = if (nzchar(p[2])) cls(flip(tk, 2), K[[kn]]) else NA,
    ek_flip_last = if (nzchar(p[2])) cls(flip(tk, 2, length(unb64(p[2]))), K[[kn]]) else NA,
    ek_trunc = if (nzchar(p[2])) cls(jn(c(p[1], b64(unb64(p[2])[-1]), p[3:5])), K[[kn]]) else NA,
    ek_empty = cls(jn(c(p[1], "", p[3:5])), K[[kn]]),
    ek_extra = cls(jn(c(p[1], b64(c(unb64(p[2] ), raw(8))), p[3:5])), K[[kn]]),
    iv_flip = cls(flip(tk, 3), K[[kn]]), ct_flip = cls(flip(tk, 4), K[[kn]]), tag_flip = cls(flip(tk, 5), K[[kn]]),
    ct_trunc = cls(jn(c(p[1:3], b64(unb64(p[4])[-1]), p[5])), K[[kn]]),
    iv_trunc = cls(jn(c(p[1:2], b64(unb64(p[3])[-1]), p[4:5])), K[[kn]])
  )
  cat(n, ":", length(unique(na.omit(res))), "distinct\n"); if (length(unique(na.omit(res))) > 1) print(res)
}
# wrong key same type
cat(cls(t$dir_gcm, jwk_oct(as.raw(1:32))), "\n"); cat(cls(t$kw, jwk_oct(as.raw(1:16))), "\n"); cat(cls(t$pbes2, jwk_oct(charToRaw("wrong"))), "\n")
k2 <- jwk_generate("RSA"); cat(cls(t$oaep, k2), "\n"); cat(cls(t$rsa15, k2), "\n"); cat(cls(t$ecdh_p256, K$p256b), "\n")
cat(cls(t$oaep, jwk_public(K$rsa)), "\n"); cat(cls(t$ecdh_p256, jwk_public(K$p256)), "\n")
cat(cls(t$dir_gcm, K$oct16), "\n"); cat(cls(t$dir_cbc, K$oct16), "\n")
