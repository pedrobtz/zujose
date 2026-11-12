source("pre.R")
set.seed(2)
rsa <- jwk_generate("RSA", kid = "rsa-1")
ec <- list(ES256 = "P-256", ES384 = "P-384", ES512 = "P-521")
hs <- c(HS256 = 256, HS384 = 384, HS512 = 512)
keyfor <- function(a) if (a %in% names(hs)) jwk_generate("oct", alg = a) else if (a %in% names(ec)) jwk_generate("EC", crv = ec[[a]], kid = paste0("ec-", a)) else rsa
algs <- c(names(hs), "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", names(ec))
payloads <- list("", "hello", "héllo wörld ☃", as.raw(sample(0:255, 300, TRUE)), '{"a":1}', "a.b.c")
for (a in algs) for (fmt in c("compact", "flattened", "general")) for (b64 in c(TRUE, FALSE)) for (det in c(TRUE, FALSE)) for (pi in seq_along(payloads)) {
  k <- keyfor(a); p <- payloads[[pi]]
  unp <- if (fmt != "compact" && pi %% 2 == 0) list(x = "y", n = 3L) else NULL
  hdr <- if (pi %% 3 == 0) list(typ = "é/x", extra = list(1, "a", TRUE)) else NULL
  tok <- try_(jws_sign(p, k, alg = a, header = hdr, unprotected = unp, format = fmt, b64 = b64, detached = det))
  if (inherits(tok, "err")) { cat("ERR", a, fmt, b64, det, pi, tok$msg, "\n"); next }
  pb <- if (is.raw(p)) p else charToRaw(enc2utf8(p))
  rt <- try_(jws_verify(tok, k, a, payload = if (det) pb))
  if (inherits(rt, "err") || !identical(rt$payload, pb)) cat("SELF FAIL", a, fmt, b64, det, pi, if (inherits(rt,"err")) rt$msg, "\n")
  add(name = paste(a, fmt, b64, det, pi), alg = a, token = tok, key = jwk_json(k, private = TRUE), pub = if (k$kty == "oct") "" else jwk_json(jwk_public(k)), payload = hexs(pb), det = det, b64 = b64, fmt = fmt, kid = k$kid %||% "")
}
# many ES sigs for leading zeros
for (a in names(ec)) { k <- keyfor(a); for (i in 1:700) {
  tok <- jws_sign(sprintf("m%d", i), k, alg = a)
  add(name = paste("many", a, i), alg = a, token = tok, key = jwk_json(k, private = TRUE), pub = jwk_json(jwk_public(k)), payload = hexs(charToRaw(sprintf("m%d", i))), det = FALSE, b64 = TRUE, fmt = "compact", kid = k$kid)
} }
# several signers
k1 <- jwk_generate("oct", alg = "HS256", kid = "h"); k2 <- keyfor("ES384"); k3 <- rsa
tok <- jws_sign("multi", list(jws_signer(k1, "HS256"), jws_signer(k2, "ES384", header = list(typ = "x"), unprotected = list(u = 1L)), jws_signer(k3, "PS512")), format = "general")
for (k in list(k1, k2, k3)) add(name = paste("multi", k$kty), alg = "multi", token = tok, key = jwk_json(k, private = TRUE), pub = "", payload = hexs(charToRaw("multi")), det = FALSE, b64 = TRUE, fmt = "general", kid = k$kid)
flush_out("p02.json"); cat(length(OUT), "\n")
