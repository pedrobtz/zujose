source("../hunt-1/pre.R")
T <- function(label, expr) { cat("==", label, ": "); r <- tryCatch(expr, error=function(e) paste0("ERROR<", class(e)[1], "> ", conditionMessage(e))); cat(if (is.character(r)) r else format(r), "\n") }
b64 <- function(x) zuutf::base64_encode(if (is.character(x)) charToRaw(x) else x, url=TRUE, pad=FALSE)
# H2-1 oth
rk <- jwk_generate("RSA", size=2048); m <- zujson::json_parse(jwk_json(rk, TRUE))
m$oth <- list(list(r="AQAB", d="AQAB", t="AQAB"))
T("oth accepted", { k <- as_jwk(zujson::json_write(m)); paste("supported", k$supported) })
# H2-2 X25519 x zero
xk <- jwk_generate("OKP", crv="X25519"); m <- zujson::json_parse(jwk_json(xk, TRUE))
m$x <- b64(as.raw(rep(0,32)))
T("x25519 bogus x", { k <- as_jwk(zujson::json_write(m)); jwk_json(jwk_public(k)) })
m$x <- "AA"; T("x25519 1-byte x", { as_jwk(zujson::json_write(m)); "accepted" })
# H2-4 p2c Inf
pw <- jwk_oct(charToRaw("password-password"))
h <- b64('{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2s":"AAAAAAAAAAAAAAAAAAAAAA","p2c":4294967296}')
tok <- paste(h, b64(as.raw(1:24)), b64(as.raw(1:12)), b64("x"), b64(as.raw(1:16)), sep=".")
T("p2c huge Inf limit", { jwe_decrypt(tok, pw, "PBES2-HS256+A128KW", "A128GCM", limits=jose_limits(p2c=Inf)); "?" })
# H2-5 exp 1e308
k <- jwk_oct(as.raw(1:32))
t <- jws_sign('{"exp":1e308}', k, "HS256")
T("exp 1e308", { c <- jwt_decode(t, k, "HS256"); format(c$exp) })
# H2-6 b64 false JWT
hh <- b64('{"alg":"HS256","b64":false,"crit":["b64"]}')
si <- paste0(hh, '.{"exp":4000000000}')
sig <- b64(zucrypt::crypt_hmac(charToRaw(si), as.raw(1:32), "sha256"))
T("jwt b64 false", { c <- jwt_decode(paste0(si, ".", sig), k, "HS256"); "ACCEPTED" })
