.libPaths(c("/private/tmp/claude-501/-Users-pbtz-src-github-com-pedrobtz-zujose/d0fc5964-95dc-448e-aa22-7084d328c0dd/scratchpad/hunt/lib", .libPaths())); library(zujose)
b64 <- function(x) { if (is.character(x)) x <- charToRaw(x); if (!length(x)) return(""); zuutf::base64_encode(x, url = TRUE, pad = FALSE) }
# run expression, print class + message or result summary
try_ <- function(label, expr) {
  r <- tryCatch(list(ok = TRUE, v = expr), error = function(e) list(ok = FALSE, e = e))
  if (r$ok) cat(sprintf("[%s] OK\n", label)) else cat(sprintf("[%s] ERR <%s> %s\n", label, paste(head(class(r$e), 2), collapse = "/"), conditionMessage(r$e)))
  invisible(if (r$ok) r$v else r$e)
}
hs <- function(header_json, payload, key, hash = "sha256") {
  h <- b64(header_json); p <- if (is.raw(payload)) b64(payload) else b64(payload)
  s <- zucrypt::crypt_hmac(charToRaw(paste0(h, ".", p)), key, hash)
  paste0(h, ".", p, ".", b64(s))
}
K32 <- as.raw(1:32)
unb64 <- function(x) zuutf::base64_decode(x, url = TRUE, forgiving = FALSE, pad = FALSE)
