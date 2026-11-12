# Write tests/testthat/fixtures/oracle/zujose-tokens.tsv: tokens zujose
# signs, for PyJWT to verify (#100).
#
# Usage, from the package root, after tools/make-oracle-fixtures.py has
# written the keys:
#
#   Rscript tools/make-zujose-tokens.R
#   python3 tools/make-oracle-fixtures.py --check
#
# Maintainer tooling, never run at check time. One row per token: a JWT
# from jwt_encode() and a JWS of a non-JSON payload from jws_sign(), for
# each of HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512,
# ES256, ES384 and ES512, signed with the HMAC secret bytes 1..64 or a key
# of fixtures/oracle/*.pem. The claims are fixed, below and in
# make-oracle-fixtures.py's ZUJOSE_CLAIMS: an `aud` array, a nested object,
# non-ASCII text, and `exp`, `nbf` and `iat` given as POSIXct and as
# numbers. `--check` there verifies every token with PyJWT's jwt.decode()
# or jws.decode() and compares the claims, their types and the header
# with what is written here. tests/testthat/test-oracle.R re-verifies the
# committed tokens with zujose and signs them again, so a change to the
# emitter shows at check time as a fixture to regenerate.
#
# HS* and RS* signatures are deterministic, so writing again gives the same
# file; PS* and ES* signatures change on every write.

pkgload::load_all(quiet = TRUE)

out <- file.path("tests", "testthat", "fixtures", "oracle")
# The PyJWT that make-oracle-fixtures.py --check verifies the tokens with.
checked_with <- "PyJWT 2.15.1"

# Keep in step with ZUJOSE_CLAIMS and ZUJOSE_PAYLOAD in
# tools/make-oracle-fixtures.py.
claims <- list(
  iss = "https://issuer.example",
  sub = "u2",
  aud = list("api", "other"),
  exp = as.POSIXct(2000000000, origin = "1970-01-01", tz = "UTC"),
  nbf = 999999000,
  iat = 999999990,
  n = 42L,
  x = 1.5,
  ok = TRUE,
  none = NULL,
  name = "Zoë 日本",
  roles = list("a", "b"),
  ctx = list(tenant = "t1", depth = list(level = 2L))
)
payload <- "zujose → PyJWT: not JSON"

pem <- function(name) {
  path <- file.path(out, paste0(name, ".pem"))
  readChar(path, file.size(path), useBytes = TRUE)
}
keys <- list(
  hmac = jwk_oct(as.raw(1:64), kid = "hmac"),
  "rsa-2048" = jwk_with_kid(as_jwk(pem("rsa-2048")), "rsa-2048"),
  "ec-p256" = jwk_with_kid(as_jwk(pem("ec-p256")), "ec-p256"),
  "ec-p384" = jwk_with_kid(as_jwk(pem("ec-p384")), "ec-p384"),
  "ec-p521" = jwk_with_kid(as_jwk(pem("ec-p521")), "ec-p521")
)
algs <- c(
  HS256 = "hmac",
  HS384 = "hmac",
  HS512 = "hmac",
  RS256 = "rsa-2048",
  RS384 = "rsa-2048",
  RS512 = "rsa-2048",
  PS256 = "rsa-2048",
  PS384 = "rsa-2048",
  PS512 = "rsa-2048",
  ES256 = "ec-p256",
  ES384 = "ec-p384",
  ES512 = "ec-p521"
)

rows <- list()
for (alg in names(algs)) {
  key <- keys[[algs[[alg]]]]
  rows[[length(rows) + 1L]] <- data.frame(
    id = paste0("jwt-", tolower(alg)),
    kind = "jwt",
    alg = alg,
    key = algs[[alg]],
    token = jwt_encode(claims, key, alg, issued_at = FALSE)
  )
  rows[[length(rows) + 1L]] <- data.frame(
    id = paste0("jws-", tolower(alg)),
    kind = "jws",
    alg = alg,
    key = algs[[alg]],
    token = jws_sign(payload, key, alg)
  )
}
rows <- do.call(rbind, rows)
path <- file.path(out, "zujose-tokens.tsv")
utils::write.table(
  rows,
  path,
  sep = "\t",
  quote = FALSE,
  row.names = FALSE,
  fileEncoding = "UTF-8"
)

# The MANIFEST.tsv row; the other rows are kept.
manifest_path <- file.path(out, "MANIFEST.tsv")
manifest <- utils::read.delim(
  manifest_path,
  colClasses = "character",
  quote = ""
)
manifest <- manifest[manifest$file != "zujose-tokens.tsv", ]
manifest <- rbind(
  manifest,
  data.frame(
    file = "zujose-tokens.tsv",
    source = sprintf(
      "zujose %s; verified by %s",
      utils::packageVersion("zujose"),
      checked_with
    ),
    generator = "tools/make-zujose-tokens.R"
  )
)
utils::write.table(
  manifest,
  manifest_path,
  sep = "\t",
  quote = FALSE,
  row.names = FALSE
)
cat(sprintf("wrote %d tokens to %s\n", nrow(rows), path))
