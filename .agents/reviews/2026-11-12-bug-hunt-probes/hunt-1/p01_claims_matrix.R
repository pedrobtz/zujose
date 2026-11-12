source("pre.R")
vals <- list(
  chr2 = c("a", "bbb"), fac = factor(c("x","y")), fac1 = factor("x"), int = 5L, dbl = 1234567.891, big = 2^31 + 1, huge = 2^53 + 2, vbig=1e15, v1e5 = 1e5, v1e20=1e20, small=1e-7, third=1/3,
  lgl = TRUE, lgl2 = c(TRUE, NA), na_chr = NA_character_, na_int = NA_integer_, na_real = NA_real_, na_lgl = NA,
  nan = NaN, inf = Inf, zero_chr = character(), zero_int = integer(), date = as.Date("2026-01-02"),
  posix = as.POSIXct("2026-01-02 03:04:05", tz = "UTC"), lst = list(1, "a"), nlst = list(a = 1, b = "x"),
  named_vec = c(a = 1, b = 2), dup_named = c(a = 1, a = 2), nonascii = "café", latin1 = iconv("café", "UTF-8", "latin1"),
  newline = "a\nb", raw = as.raw(1:3), null_in = list(NULL), mat = matrix(1:4, 2), df = data.frame(a=1:2), cplx = 1i, int64ish = 9007199254740993, neg0 = -0, 
  i1 = I("a"), emptystr = "", difft = as.difftime(5, units="mins"), nested_empty = list(), named_empty = setNames(list(), character())
)
for (n in names(vals)) {
  cat("---", n, ": ")
  tok <- try_(jwt_encode(setNames(list(vals[[n]]), n), key, "HS256", issued_at = FALSE, expires_in = 100))
  if (is.character(tok)) {
    cat(payload_of(tok), "\n")
    back <- try_(jwt_decode(tok, key, "HS256"))
    if (inherits(back, "jwt_claims")) { cat("   back: "); cat(deparse(unclass(back)[[n]]), "\n") }
  }
}
