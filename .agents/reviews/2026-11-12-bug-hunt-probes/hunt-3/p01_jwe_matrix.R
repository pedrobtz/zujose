source("pre.R")
set.seed(1)
rsa <- jwk_generate("RSA", kid = "r1")
ecs <- list(`P-256` = jwk_generate("EC", crv = "P-256"), `P-384` = jwk_generate("EC", crv = "P-384"),
            `P-521` = jwk_generate("EC", crv = "P-521"), X25519 = jwk_generate("OKP", crv = "X25519"))
encs <- c("A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM")
cekb <- c(32, 48, 64, 16, 24, 32); names(cekb) <- encs
lens <- c(0, 1, 15, 16, 17, 31, 32, 33, 100)
cases <- list()
for (enc in encs) {
  cases[[length(cases)+1]] <- list(alg = "dir", key = jwk_generate("oct", size = 8 * cekb[[enc]]), enc = enc)
  for (a in c("A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW"))
    cases[[length(cases)+1]] <- list(alg = a, key = jwk_generate("oct", alg = a), enc = enc)
  for (a in c("PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"))
    cases[[length(cases)+1]] <- list(alg = a, key = jwk_oct(charToRaw("pässword-é 123")), enc = enc, header = list(p2c = 1000))
  for (a in c("RSA-OAEP", "RSA-OAEP-256")) cases[[length(cases)+1]] <- list(alg = a, key = rsa, enc = enc)
  for (crv in names(ecs)) for (a in c("ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW")) {
    cases[[length(cases)+1]] <- list(alg = a, key = ecs[[crv]], enc = enc)
    cases[[length(cases)+1]] <- list(alg = a, key = ecs[[crv]], enc = enc, header = list(apu = "QWxpY2U", apv = "Qm9i"))
  }
}
i <- 0
for (cs in cases) for (fmt in c("compact", "flattened", "general")) {
  i <- i + 1
  n <- sample(lens, 1)
  pt <- as.raw(sample(0:255, n, TRUE))
  aad <- if (fmt != "compact" && i %% 2 == 0) charToRaw('{"a":"b"}') else NULL
  unp <- if (fmt != "compact" && i %% 3 == 0) list(foo = "bar") else NULL
  pub <- if (cs$key$kty == "oct") cs$key else jwk_public(cs$key)
  tok <- try_(jwe_encrypt(pt, pub, alg = cs$alg, enc = cs$enc, header = cs$header, unprotected = unp, aad = aad, format = fmt))
  if (inherits(tok, "err")) { cat("ERR", cs$alg, cs$enc, fmt, tok$msg, "\n"); next }
  rt <- try_(jwe_decrypt(tok, cs$key, cs$alg, cs$enc))
  if (inherits(rt, "err") || !identical(rt$plaintext, pt)) cat("SELF-RT FAIL", cs$alg, cs$enc, fmt, "\n")
  add(name = paste(cs$alg, cs$enc, fmt, n, cs$key$kty, cs$key$members$crv %||% "", if (!is.null(cs$header$apu)) "apu" else ""),
      token = tok, key = jwk_json(cs$key, private = TRUE), pt = hexs(pt), aad = if (is.null(aad)) "" else hexs(aad), fmt = fmt)
}
flush_out("p01.json"); cat(length(OUT), "cases\n")
