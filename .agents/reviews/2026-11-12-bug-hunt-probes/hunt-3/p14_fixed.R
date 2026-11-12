source("pre.R")
set.seed(14); rb <- function(n) as.raw(sample(0:255, n, TRUE))
for (kl in c(16, 24, 32)) for (dl in c(16, 24, 32, 40, 48, 64, 72, 8, 20, 0)) { kek <- rb(kl); d <- rb(dl); w <- try_(zujose:::aes_key_wrap(kek, d)); add(kind = "kw", kek = hexs(kek), data = hexs(d), out = if (inherits(w, "err")) paste("ERR", w$msg) else hexs(w)) }
for (bits in c(128, 192, 256, 384, 512)) for (zl in c(32, 48, 66)) for (al in c(0, 1, 5, 255, 256, 300, 70000)) { z <- rb(zl); apu <- rb(al); apv <- rb(al %% 7); id <- sample(c("A128GCM", "ECDH-ES+A256KW", "A256CBC-HS512"), 1)
  add(kind = "kdf", z = hexs(z), bits = bits, id = id, apu = hexs(apu), apv = hexs(apv), out = hexs(zujose:::concat_kdf(z, bits, id, apu, apv))) }
encs <- c("A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM")
for (enc in encs) for (pl in c(0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 49, 1000)) for (al in c(0, 1, 100)) { cek <- rb(zujose:::cek_bytes(enc)); iv <- rb(zujose:::iv_bytes(enc)); p <- rb(pl); aad <- rb(al)
  s <- zujose:::content_encrypt(enc, cek, iv, p, aad); add(kind = "enc", enc = enc, cek = hexs(cek), iv = hexs(iv), pt = hexs(p), aad = hexs(aad), ct = hexs(s$ciphertext), tag = hexs(s$tag)) }
for (alg in c("PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW")) for (sl in c(8, 16, 100)) { pw <- rb(sample(1:80, 1)); s <- rb(sl); add(kind = "pbes2", alg = alg, pw = hexs(pw), p2s = hexs(s), p2c = 1001, out = hexs(zujose:::pbes2_kek(alg, pw, s, 1001))) }
flush_out("p14.json")
