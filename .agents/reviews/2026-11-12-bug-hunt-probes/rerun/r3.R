source("../hunt-1/pre.R")
T <- function(label, expr) { cat("==", label, ": "); r <- tryCatch(expr, error=function(e) paste0("ERROR<", class(e)[1], "> ", conditionMessage(e))); cat(if (is.character(r)) r else format(r), "\n") }
k <- jwk_oct(as.raw(1:32))
T("NUL b64false", { jws_sign(as.raw(c(0x61,0,0x62)), k, "HS256", b64=FALSE, detached=TRUE); "ok" })
ek <- jwk_generate("EC", crv="P-256", key_ops="sign", alg="ES256")
T("jwk_public key_ops", { jws_verify(jws_sign("p", ek), jwk_public(ek), "ES256"); "verified" })
T("dup header", header_of(jws_sign("p", k, "HS256", header=list(a=1, a=2))))
T("complex claim", { jwt_encode(list(a=1i), k, "HS256"); "ok" })
T("set[[9]]", { jwk_set(k)[[9]]; "ok" })
