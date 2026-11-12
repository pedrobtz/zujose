source("helper.R")
d <- zujson::json_parse(paste(readLines("data/jwe.json", warn = FALSE), collapse = "\n"), simplify = "none")
K <- lapply(d$keys, as_jwk); t <- zujson::json_parse(paste(readLines("data/jwe2.json", warn = FALSE), collapse = "\n"), simplify = "none")
ALG <- zujose_info(); KM <- ALG$algorithm[ALG$kind == "key management"]; CE <- ALG$algorithm[ALG$kind == "content encryption"]
dec <- function(label, tok, key, algorithms = KM, encryptions = CE, ...) {
  r <- try_(label, jwe_decrypt(tok, key, algorithms = algorithms, encryptions = encryptions, ...))
  invisible(r)
}
for (n in names(t)) { key <- if (grepl("^p2", n)) K$pw else if (grepl("^x_", n)) K$x25519 else K[[sub(".*_", "", n)]]; dec(n, t[[n]], key) }
dec("p2c 2000 limit 2000", t$p2c_2000, K$pw, limits = jose_limits(p2c = 2000)); dec("p2c 2001 limit 2000", t$p2c_2001, K$pw, limits = jose_limits(p2c = 2000))
dec("p2c 1e400 limit Inf", t$p2c_1e400, K$pw, limits = jose_limits(p2c = Inf)); dec("p2c 2^32 limit Inf", t$p2c_big, K$pw, limits = jose_limits(p2c = Inf)); 
# does a p2c over limit get rejected before key resolution? resolver spy
seen <- FALSE; dec("p2c over limit, resolver", t$p2c_600001, function(h) { seen <<- TRUE; K$pw }); cat("resolver called:", seen, "\n")
seen <- FALSE; dec("offcurve epk, resolver", t$ec_offcurve_p256, function(h) { seen <<- TRUE; K$p256 }); cat("resolver called:", seen, "\n")
