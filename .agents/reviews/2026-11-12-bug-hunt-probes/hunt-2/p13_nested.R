source("helper.R")
key <- jwk_oct(K32); NOW <- as.POSIXct(1000, origin = "1970-01-01", tz = "UTC")
CEK <- as.raw(200:231); kd <- jwk_oct(CEK)
gcm <- function(hdr, pt, cek = CEK) { h <- b64(hdr); iv <- as.raw(1:12); if (is.character(pt)) pt <- charToRaw(pt); s <- zucrypt::crypt_aes_gcm_encrypt(pt, cek, iv, aad = charToRaw(h)); paste(h, "", b64(iv), b64(as.vector(s)), b64(attr(s, "tag")), sep = ".") }
D <- jwe_decryption(kd, "dir", "A256GCM")
jd <- function(label, tok, ..., dk = D) { r <- try_(label, jwt_decode(tok, key, "HS256", now = NOW, decrypt = dk, ...)); if (inherits(r, "jwt_claims")) cat("     claims:", zujson::json_write(lapply(unclass(r), as.numeric)), " header:", zujson::json_write(attr(r, "header")), "\n"); invisible(r) }
inner <- hs('{"alg":"HS256","typ":"JWT"}', '{"exp":2000,"sub":"in"}', K32)
cat("--- nested JWS in JWS\n")
jd("jws(cty JWT) > jws", hs('{"alg":"HS256","cty":"JWT"}', inner, K32))
jd("cty jwt lower", hs('{"alg":"HS256","cty":"jwt"}', inner, K32)); jd("cty application/jwt", hs('{"alg":"HS256","cty":"application/JWT"}', inner, K32))
jd("no cty, payload is jws", hs('{"alg":"HS256"}', inner, K32))
jd("cty JWT but payload claims", hs('{"alg":"HS256","cty":"JWT"}', '{"exp":2000}', K32))
jd("cty other", hs('{"alg":"HS256","cty":"text"}', '{"exp":2000}', K32))
jd("outer typ at+jwt inner typ JWT, type JWT", hs('{"alg":"HS256","cty":"JWT","typ":"at+jwt"}', inner, K32))
inner_at <- hs('{"alg":"HS256","typ":"at+jwt"}', '{"exp":2000}', K32)
jd("outer typ JWT inner typ at+jwt, type JWT", hs('{"alg":"HS256","cty":"JWT","typ":"JWT"}', inner_at, K32))
jd("outer typ JWT inner at+jwt, type at+jwt", hs('{"alg":"HS256","cty":"JWT","typ":"JWT"}', inner_at, K32), type = "at+jwt")
jd("3 levels", hs('{"alg":"HS256","cty":"JWT"}', hs('{"alg":"HS256","cty":"JWT"}', inner, K32), K32))
jd("inner bad sig", hs('{"alg":"HS256","cty":"JWT"}', sub(".$", "A", inner), K32))
jd("inner alg HS512 not allowed", hs('{"alg":"HS256","cty":"JWT"}', hs('{"alg":"HS512"}', '{"exp":2000}', as.raw(1:64), "sha512"), K32))
jd("inner is JWE", hs('{"alg":"HS256","cty":"JWT"}', gcm('{"alg":"dir","enc":"A256GCM"}', '{"exp":2000}'), K32))
jd("inner JSON serialization", hs('{"alg":"HS256","cty":"JWT"}', '{"payload":"e30","protected":"e30","signature":""}', K32))
jd("inner with NUL", hs('{"alg":"HS256","cty":"JWT"}', as.raw(c(0x61, 0, 0x2e, 0x62, 0x2e, 0x63)), K32))
jd("inner expired, outer n/a", hs('{"alg":"HS256","cty":"JWT"}', hs('{"alg":"HS256"}', '{"exp":10}', K32), K32))
jd("outer limits apply to inner? payload limit", hs('{"alg":"HS256","cty":"JWT"}', inner, K32), limits = jose_limits(payload = 40))
# inner key different from outer key: resolver gets which headers
seen <- list(); r <- try_("resolver nested", jwt_decode(hs('{"alg":"HS256","cty":"JWT","kid":"outer"}', hs('{"alg":"HS256","kid":"inner"}', '{"exp":2000}', K32), K32), function(h) { seen[[length(seen) + 1]] <<- h; key }, "HS256", now = NOW)); cat(vapply(seen, zujson::json_write, ""), "\n")
cat("--- JWE\n")
jd("jwe dir claims", gcm('{"alg":"dir","enc":"A256GCM"}', '{"exp":2000,"sub":"e"}'))
jd("jwe dir claims, decrypt NULL", gcm('{"alg":"dir","enc":"A256GCM"}', '{"exp":2000}'), dk = NULL)
jd("jwe dir claims typ at+jwt", gcm('{"alg":"dir","enc":"A256GCM","typ":"at+jwt"}', '{"exp":2000}'))
jd("jwe cty JWT > jws", gcm('{"alg":"dir","enc":"A256GCM","cty":"JWT"}', inner))
jd("jwe no cty, pt is jws", gcm('{"alg":"dir","enc":"A256GCM"}', inner))
jd("jwe cty JWT > jws(cty JWT) > jws", gcm('{"alg":"dir","enc":"A256GCM","cty":"JWT"}', hs('{"alg":"HS256","cty":"JWT"}', inner, K32)))
jd("jwe cty JWT > jwe", gcm('{"alg":"dir","enc":"A256GCM","cty":"JWT"}', gcm('{"alg":"dir","enc":"A256GCM"}', '{"exp":2000}')))
jd("jwe cty JWT > claims", gcm('{"alg":"dir","enc":"A256GCM","cty":"JWT"}', '{"exp":2000}'))
jd("jwe expired", gcm('{"alg":"dir","enc":"A256GCM"}', '{"exp":10}'))
jd("jwe claims aud no arg", gcm('{"alg":"dir","enc":"A256GCM"}', '{"exp":2000,"aud":"x"}'))
jd("jwe zip", gcm('{"alg":"dir","enc":"A256GCM","zip":"DEF"}', '{"exp":2000}'))
jd("jwe JSON", sprintf('{"protected":"%s","iv":"AAAAAAAAAAAAAAAA","ciphertext":"AA","tag":"AAAAAAAAAAAAAAAAAAAAAA"}', b64('{"alg":"dir","enc":"A256GCM"}')))
try_("decrypt not jwe_decryption", jwt_decode(inner, key, "HS256", now = NOW, decrypt = list(key = kd)))
try_("jws with decrypt set", jwt_decode(inner, key, "HS256", now = NOW, decrypt = D))
# 5-part token with HS256 header (JWS alg in a JWE shape)
jd("jwe alg HS256", gcm('{"alg":"HS256","enc":"A256GCM"}', '{"exp":2000}'))
# asymmetric: encrypted-only refused
d <- zujson::json_parse(paste(readLines("data/jwe.json", warn = FALSE), collapse = "\n"), simplify = "none"); K <- lapply(d$keys, as_jwk)
ALG <- zujose_info(); KM <- ALG$algorithm[ALG$kind == "key management"]; CE <- ALG$algorithm[ALG$kind == "content encryption"]
for (n in c("oaep", "rsa15", "ecdh_p256", "ecdhkw_x25519", "kw", "gcmkw", "pbes2", "dir_gcm", "dir_cbc")) {
  kn <- c(oaep = "rsa", rsa15 = "rsa", ecdh_p256 = "p256", ecdhkw_x25519 = "x25519", kw = "oct16", gcmkw = "oct32", pbes2 = "pw", dir_gcm = "oct32", dir_cbc = "oct32")[[n]]
  jd(paste("py", n), d$tok[[n]], dk = jwe_decryption(K[[kn]], KM, CE))
}
# is the policy refusal (asymmetric, no cty) before decrypt? resolver spy
seen <- FALSE; jd("oaep enc-only resolver", d$tok$oaep, dk = jwe_decryption(function(h) { seen <<- TRUE; K$rsa }, KM, CE)); cat("resolver called:", seen, "\n")
# JWE where protected says cty JWT is absent but the *unprotected*... compact only. ok.
# symmetric JWE with cty:"JWT" in header but key for inner = same oct key used as dir key? confusion: use HS key as dir key
