source("pre.R")
b <- function(s) zujose:::b64url_decode(s, "x", NULL); e <- zujose:::b64url_encode
k <- jwk_generate("RSA")
j2 <- sub('"e":"AQAB"', '"e":"AAEAAQ"', jwk_json(k), fixed = TRUE)
k2 <- as_jwk(j2)
add(name = "rsa e AAEAAQ", canon = jwk_json(k), given = j2, out = jwk_json(k2), tp_canon = jwk_thumbprint(k), tp = jwk_thumbprint(k2), pem_same = identical(jwk_pem(k), jwk_pem(k2)))
j3 <- sub(k$members$n, e(c(as.raw(0), b(k$members$n))), jwk_json(k), fixed = TRUE)
k3 <- try_(as_jwk(j3))
if (!inherits(k3, "err")) add(name = "rsa n lead0", canon = jwk_json(k), given = j3, out = jwk_json(k3), tp_canon = jwk_thumbprint(k), tp = jwk_thumbprint(k3), pem_same = identical(jwk_pem(k), jwk_pem(k3)), bits = k3$bits) else cat("rsa n lead0 refused:", k3$msg, "\n")
for (crv in c("P-256", "P-521")) {
  repeat { ec <- jwk_generate("EC", crv = crv); if (b(ec$members$x)[1] == 0) break }
  short <- sub(ec$members$x, e(b(ec$members$x)[-1]), jwk_json(ec, TRUE), fixed = TRUE)
  long <- sub(ec$members$y, e(c(as.raw(0), b(ec$members$y))), jwk_json(ec, TRUE), fixed = TRUE)
  for (v in list(list("short x", short), list("long y", long))) {
    k2 <- try_(as_jwk(v[[2]]))
    if (inherits(k2, "err")) { cat(crv, v[[1]], "refused:", k2$msg, "\n"); next }
    tok <- jwe_encrypt("hi", jwk_public(k2), "ECDH-ES", "A128GCM")
    add(name = paste(crv, v[[1]]), canon = jwk_json(ec), given = v[[2]], out = jwk_json(k2), tp_canon = jwk_thumbprint(ec), tp = jwk_thumbprint(k2), pem_same = identical(jwk_pem(ec), jwk_pem(k2)), kid = jwk_with_kid(k2)$kid)
  }
}
x <- jwk_generate("OKP")
flush_out("p06.json")
for (o in OUT) { cat(o$name, ": thumbprint equal to canonical:", o$tp == o$tp_canon, "| json re-emitted as given:", !identical(o$out, o$canon), "| pem same:", o$pem_same, "\n") }
