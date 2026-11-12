.libPaths(c("/private/tmp/claude-501/-Users-pbtz-src-github-com-pedrobtz-zujose/d0fc5964-95dc-448e-aa22-7084d328c0dd/scratchpad/hunt/lib", .libPaths())); library(zujose)
dec <- function(x) rawToChar(zuutf::base64_decode(x, url = TRUE, forgiving = FALSE, pad = FALSE))
parts <- function(tok) strsplit(tok, ".", fixed = TRUE)[[1]]
try_ <- function(expr) tryCatch(expr, error = function(e) cat("ERROR<", paste(class(e), collapse=","), ">:", conditionMessage(e), "\n"), warning = function(w) cat("WARNING<", paste(class(w), collapse=","), ">:", conditionMessage(w), "\n"))
key <- jwk_oct(as.raw(1:32), kid = "k1")
payload_of <- function(tok) dec(parts(tok)[2])
header_of <- function(tok) dec(parts(tok)[1])
