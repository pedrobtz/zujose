source("pre.R")
R <- function(label, expr) { r <- try_(expr); cat(sprintf("%-40s", label)); if (inherits(r, "err")) cat("ERR", r$cls[1], "|", r$msg, "\n") else cat("ok", if (is.character(r)) nchar(r) else "", "\n"); invisible(r) }
k <- jwk_oct(as.raw(1:32), kid = "kk", alg = "HS256"); kw <- jwk_generate("oct", alg = "A128KW")
for (n in c(16, 17)) { t <- jws_sign("p", rep(list(jws_signer(k)), n), format = "general"); R(paste(n, "signers self-verify"), jws_verify(t, k, "HS256")$payload) }
for (n in c(16, 17)) { t <- jwe_encrypt("p", rep(list(jwe_recipient(kw)), n), format = "general"); R(paste(n, "recipients self-decrypt"), jwe_decrypt(t, kw, "A128KW", "A128CBC-HS256")$plaintext) }
# payload sizes: limit payload 2^20, token 2^20
for (n in c(786000, 786400, 786432, 2^20 - 1, 2^20, 2^20 + 1)) { t <- R(paste("jws_sign payload bytes", n), jws_sign(raw(n), k)); if (is.character(t)) R("   self-verify", length(jws_verify(t, k, "HS256")$payload)) }
for (n in c(2^20 - 100, 2^20, 2^20 + 1)) { t <- R(paste("jws b64=F flattened payload", n), jws_sign(strrep("a", n), k, b64 = FALSE, format = "flattened")); if (is.character(t)) R("   self-verify", length(jws_verify(t, k, "HS256")$payload)) }
for (n in c(2^20 - 200, 2^20)) { t <- R(paste("jws detached payload", n), jws_sign(raw(n), k, detached = TRUE)); if (is.character(t)) R("   self-verify", length(jws_verify(t, k, "HS256", payload = raw(n))$payload)) }
for (n in c(786000, 786300, 2^20)) { t <- R(paste("jwe plaintext bytes", n), jwe_encrypt(raw(n), kw, enc = "A128GCM")); if (is.character(t)) R("   self-decrypt", length(jwe_decrypt(t, kw, "A128KW", "A128GCM")$plaintext)) }
# header size 2^14
for (n in c(12000, 12250, 16384, 20000)) { t <- R(paste("jws header member chars", n), jws_sign("p", k, header = list(x = strrep("a", n)))); if (is.character(t)) R("   self-verify", jws_verify(t, k, "HS256")$payload) }
for (n in c(12000, 20000)) { t <- R(paste("jwe header member chars", n), jwe_encrypt("p", kw, header = list(x = strrep("a", n)))); if (is.character(t)) R("   self-decrypt", jwe_decrypt(t, kw, "A128KW", "A128CBC-HS256")$plaintext) }
for (n in c(12000, 20000)) { t <- R(paste("jws unprotected header chars", n), jws_sign("p", k, unprotected = list(x = strrep("a", n)), format = "flattened")); if (is.character(t)) R("   self-verify", jws_verify(t, k, "HS256")$payload) }
# apu long
ec <- jwk_generate("EC")
t <- R("apu 13000 bytes", jwe_encrypt("p", jwk_public(ec), "ECDH-ES", "A128GCM", header = list(apu = zujose:::b64url_encode(raw(13000))))); if (is.character(t)) R("   self-decrypt", jwe_decrypt(t, ec, "ECDH-ES", "A128GCM")$plaintext)
# kid long
t <- R("b64false newline compact", jws_sign("a b~c\n", k, b64 = FALSE)); R("   self-verify", rawToChar(jws_verify(t, k, "HS256")$payload))
t <- R("b64false empty compact", jws_sign("", k, b64 = FALSE)); R("   self-verify", length(jws_verify(t, k, "HS256")$payload))
t <- R("b64 empty compact", jws_sign("", k)); R("   self-verify", length(jws_verify(t, k, "HS256")$payload))
t <- R("b64 empty flattened", jws_sign("", k, format = "flattened")); cat(t, "\n"); R("   self-verify", length(jws_verify(t, k, "HS256")$payload))
t <- R("empty detached flattened", jws_sign("", k, format = "flattened", detached = TRUE)); R("   self-verify w/ payload", length(jws_verify(t, k, "HS256", payload = raw())$payload))
t <- R("jwe empty flattened", jwe_encrypt("", kw, format = "flattened")); cat(t, "\n"); R("   self-decrypt", length(jwe_decrypt(t, kw, "A128KW", "A128CBC-HS256")$plaintext))
t <- R("jwe empty GCM compact", jwe_encrypt(raw(), kw, enc = "A256GCM")); cat(t, "\n"); R("   self-decrypt", length(jwe_decrypt(t, kw, "A128KW", "A256GCM")$plaintext))
t <- R("jwe empty aad", jwe_encrypt("x", kw, aad = "", format = "flattened")); cat(t, "\n"); R("   self-decrypt", length(jwe_decrypt(t, kw, "A128KW", "A128CBC-HS256")$plaintext))
writeLines(c(t), "p10_emptyaad.txt"); writeLines(jwk_json(kw, TRUE), "p10_key.json")
