source("pre.R")
now <- as.POSIXct(1000, origin = "1970-01-01", tz = "UTC")
tok <- jws_sign('{"exp":2000,"scope":"read"}', key, "HS256", header = list(typ = "JWT"))
cat("--- dup spec: second expectation ignored?\n")
r <- try_(jwt_decode(tok, key, "HS256", now = now, claims = list(scope = function(v) TRUE, scope = function(v) { cat("second called\n"); FALSE })))
print(inherits(r, "jwt_claims"))
r <- try_(jwt_decode(tok, key, "HS256", now = now, claims = list(scope = "read", scope = "write")))
print(inherits(r, "jwt_claims"))

cat("--- jws_sign value matrix on payload\n")
for (p in list("a", c("a","b"), factor("a"), 1L, NA_character_, NULL, character(), raw(), "", list("a"), as.raw(c(0xff, 0x00)), "café", iconv("café", "UTF-8", "latin1"), "a\nb", TRUE)) {
  cat(deparse(p), ": "); r <- try_(jws_sign(p, key, "HS256")); if (is.character(r)) { cat(r, "\n"); v <- try_(jws_verify(r, key, "HS256")); if (inherits(v, "jws_verified")) cat("   payload back:", deparse(v$payload), "\n") }
}
cat("--- formats\n")
for (f in c("compact", "flattened", "general")) for (b64 in c(TRUE, FALSE)) for (det in c(TRUE, FALSE)) for (p in list("hello", "", "a.b", "café \"q\" \n", as.raw(c(0xff,0xfe)))) {
  r <- tryCatch(jws_sign(p, key, "HS256", format = f, b64 = b64, detached = det, unprotected = if (f != "compact") list(x = 1)), error = function(e) e)
  lab <- sprintf("%s b64=%s det=%s p=%s", f, b64, det, paste(deparse(p), collapse=""))
  if (inherits(r, "error")) { cat(lab, "SIGN ERR:", conditionMessage(r), "\n"); next }
  v <- tryCatch(jws_verify(r, key, "HS256", payload = if (det) p), error = function(e) e)
  want <- if (is.raw(p)) p else charToRaw(enc2utf8(p))
  if (inherits(v, "error")) cat(lab, "VERIFY ERR:", conditionMessage(v), "| token:", r, "\n")
  else if (!identical(v$payload, want)) cat(lab, "PAYLOAD MISMATCH", deparse(v$payload), "\n")
}
cat("formats done\n")
cat("--- detached empty payload general no det:\n"); r <- jws_sign("", key, "HS256", format = "flattened"); cat(r, "\n"); print(try_(jws_verify(r, key, "HS256")$payload))
cat("--- compact empty, verify w/ payload arg 'x' (should fail signature)\n"); r <- jws_sign("", key, "HS256"); try_(jws_verify(r, key, "HS256", payload = "x")); print(try_(jws_verify(r, key, "HS256", payload = "")$payload))
cat("--- detached verify without payload\n"); r <- jws_sign("hello", key, "HS256", detached = TRUE); try_(print(jws_verify(r, key, "HS256")))
cat("--- unprotected dup names\n"); r <- try_(jws_sign("x", key, "HS256", format = "flattened", unprotected = list(x = 1, x = 2))); print(r); if (is.character(r)) try_(jws_verify(r, key, "HS256"))
cat("--- unprotected kid\n"); r <- try_(jws_sign("x", key, "HS256", format = "flattened", unprotected = list(kid = "u"))); print(r)
cat("--- header + unprotected same name\n"); try_(jws_sign("x", key, "HS256", format = "flattened", header = list(a = 1), unprotected = list(a = 2)))
cat("--- header b64\n"); try_(jws_sign("x", key, "HS256", header = list(b64 = FALSE)))
cat("--- header crit\n"); try_(jws_sign("x", key, "HS256", header = list(crit = list("exp"), exp = 1)))
cat("--- header partial 'al'\n"); r <- try_(jws_sign("x", key, "HS256", header = list(al = "zzz"))); if (is.character(r)) cat(header_of(r), "\n")
cat("--- header 'ki' partial\n"); r <- try_(jws_sign("x", key, "HS256", header = list(ki = "zzz"))); if (is.character(r)) cat(header_of(r), "\n")
cat("--- b64 arg variants\n"); for (b in list(NA, 1, "TRUE", c(TRUE, FALSE), NULL)) try_(jws_sign("x", key, "HS256", b64 = b))
cat("--- format variants\n"); for (f in list("Compact", c("general","compact"), NA, 1, "gen", factor("compact"), NULL)) { r <- try_(jws_sign("x", key, "HS256", format = f)); if (is.character(r)) cat(deparse(f), "->", r, "\n") }
cat("--- signer route vs direct\n")
s <- jws_signer(key, "HS256", header = list(typ = "JWT"))
a <- jws_sign("x", list(s), format = "compact"); b <- jws_sign("x", key, "HS256", header = list(typ = "JWT")); print(identical(a, b))
a <- jws_sign("x", list(s), format = "general"); b <- jws_sign("x", key, "HS256", header = list(typ = "JWT"), format = "general"); print(identical(a, b)); cat(a, "\n")
cat("--- signer captures key at creation\n")
k2 <- jwk_oct(as.raw(1:32), kid = "A"); s <- jws_signer(k2, "HS256"); k2 <- jwk_with_kid(k2, "B"); cat(header_of(jws_sign("x", list(s))), "\n")
cat("--- two signers, same key\n"); g <- jws_sign("x", list(jws_signer(key, "HS256"), jws_signer(jwk_oct(as.raw(1:64), kid = "k2"), "HS512")), format = "general"); cat(g, "\n")
v <- jws_verify(g, jwk_set(key, jwk_oct(as.raw(1:64), kid = "k2")), c("HS256", "HS512")); print(v); str(lapply(v$signatures, `[`, c("kid","alg")))
v <- try_(jws_verify(g, key, c("HS256", "HS512"))); 
v <- try_(jws_verify(g, key, c("HS256", "HS512"), require = "any")); print(v)
v <- try_(jws_verify(g, key, c("HS256"), require = "any")); print(v$alg)
cat("--- named list of signers\n"); g <- try_(jws_sign("x", list(a = jws_signer(key, "HS256")), format = "general")); print(g)
cat("--- signer list in compact with alg\n"); try_(jws_sign("x", list(jws_signer(key)), alg = "HS256"))
cat("--- signer with alg NULL & key alg NULL\n"); try_(jws_sign("x", list(jws_signer(key))))
cat("--- verify: algorithms variants\n"); t1 <- jws_sign("x", key, "HS256")
for (a in list(NULL, character(), NA_character_, "none", c("HS256", "none"), factor("HS256"), c("HS256","HS256"), "HS512", c(a = "HS256"), list("HS256"))) { cat(deparse(a), ": "); r <- try_(jws_verify(t1, key, a)); if (inherits(r, "jws_verified")) cat("ok\n") }
cat("--- verify missing algorithms\n"); try_(jws_verify(t1, key))
cat("--- verify token variants\n"); for (tk in list(c(t1, t1), NA_character_, 1, NULL, factor(t1), paste0(t1, "\n"), paste0(" ", t1), paste0(t1, "."), toupper(t1), list(t1))) { cat(substr(paste(deparse(tk), collapse=""), 1, 30), ": "); r <- try_(jws_verify(tk, key, "HS256")); if (inherits(r, "jws_verified")) cat("ok\n") }
cat("--- print verified\n"); print(jws_verify(t1, key, "HS256")); str(unclass(jws_verify(t1, key, "HS256")))
