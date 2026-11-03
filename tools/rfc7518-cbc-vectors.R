# Extract the AES_CBC_HMAC_SHA2 test cases of RFC 7518 Appendix B into
# tests/testthat/fixtures/rfc7518-cbc.tsv: one row per case, with K, P, IV,
# A, E and T in hex.
#
# Usage, from the package root:
#
#   curl -sSfo rfc7518.txt https://www.rfc-editor.org/rfc/rfc7518.txt
#   Rscript tools/rfc7518-cbc-vectors.R rfc7518.txt

args <- commandArgs(trailingOnly = TRUE)
stopifnot(length(args) == 1L, file.exists(args[[1]]))
lines <- readLines(args[[1]], warn = FALSE)

cases <- c(
  "A128CBC-HS256" = "^B\\.1\\.  ",
  "A192CBC-HS384" = "^B\\.2\\.  ",
  "A256CBC-HS512" = "^B\\.3\\.  "
)
ends <- c("^B\\.2\\.  ", "^B\\.3\\.  ", "^Appendix C\\.  ")
fields <- c("K", "P", "IV", "A", "E", "T")

rows <- list()
for (i in seq_along(cases)) {
  from <- grep(cases[[i]], lines)
  to <- grep(ends[[i]], lines)
  stopifnot(length(from) == 1L, length(to) == 1L)
  block <- lines[from:(to - 1L)]
  block <- block[!grepl("^(Jones|RFC 7518) ", block)]
  values <- list()
  current <- NULL
  for (line in block) {
    m <- regmatches(
      line,
      regexec("^     ([A-Z_]+) += +(([0-9a-f]{2} ?)+)$", line)
    )[[1]]
    if (length(m)) {
      current <- m[[2]]
      values[[current]] <- m[[3]]
    } else if (!is.null(current) && grepl("^ {15}([0-9a-f]{2} ?)+$", line)) {
      values[[current]] <- paste(values[[current]], trimws(line))
    } else {
      current <- NULL
    }
  }
  hex <- vapply(fields, function(f) gsub(" ", "", values[[f]]), "")
  rows[[i]] <- data.frame(enc = names(cases)[[i]], t(hex))
}
out <- do.call(rbind, rows)
path <- file.path("tests", "testthat", "fixtures", "rfc7518-cbc.tsv")
con <- file(path, "w")
writeLines(
  sprintf(
    "# RFC 7518 Appendix B <https://www.rfc-editor.org/rfc/rfc7518.txt>, sha256 %s, extracted by tools/rfc7518-cbc-vectors.R",
    unname(tools::sha256sum(args[[1]]))
  ),
  con
)
utils::write.table(out, con, sep = "\t", quote = FALSE, row.names = FALSE)
close(con)
cat(nrow(out), "cases written to", path, "\n")
