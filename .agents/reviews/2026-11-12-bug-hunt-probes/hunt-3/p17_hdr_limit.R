source("pre.R")
k <- jwk_oct(as.raw(1:32)); kw <- jwk_oct(as.raw(1:16))
for (extra in list(NULL, list(a = "b"), list(a = "bc"), list(a = "bcd"))) {
  t <- jws_sign("payload", k, "HS256", header = extra); h <- strsplit(t, ".", fixed = TRUE)[[1]][1]; n <- length(zujose:::b64url_decode(h, "x", NULL))
  res <- vapply((n - 4):(n + 1), function(l) !inherits(try_(jws_verify(t, k, "HS256", limits = jose_limits(header = l))), "err"), NA)
  cat("JWS header bytes", n, "b64 chars", nchar(h), " accepted at limits", paste((n - 4):(n + 1), res, collapse = " "), "\n")
  t <- jwe_encrypt("p", kw, "A128KW", header = extra); h <- strsplit(t, ".", fixed = TRUE)[[1]][1]; n <- length(zujose:::b64url_decode(h, "x", NULL))
  res <- vapply((n - 4):(n + 1), function(l) !inherits(try_(jwe_decrypt(t, kw, "A128KW", "A128CBC-HS256", limits = jose_limits(header = l))), "err"), NA)
  cat("JWE header bytes", n, "b64 chars", nchar(h), " accepted at limits", paste((n - 4):(n + 1), res, collapse = " "), "\n")
}
for (p in c("payload", "payloa", "payl", "payload12")) { t <- jws_sign(p, k, "HS256"); n <- nchar(p)
  res <- vapply((n - 3):(n + 1), function(l) !inherits(try_(jws_verify(t, k, "HS256", limits = jose_limits(payload = l))), "err"), NA)
  cat("JWS payload bytes", n, " accepted at limits", paste((n - 3):(n + 1), res, collapse = " "), "\n") }
