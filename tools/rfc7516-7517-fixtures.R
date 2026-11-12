# Extract the RFC 7517 and RFC 7516 known answers that the RFC 7520
# fixtures do not hold:
#
#   - tests/testthat/fixtures/rfc7517/: the three example JWK Sets of
#     RFC 7517 Appendix A (jwks-a1.json, jwks-a2.json, jwks-a3.json), and
#     every value of Appendix C, PBES2-HS256+A128KW with A128CBC-HS256, in
#     VALUES.tsv;
#   - tests/testthat/fixtures/rfc7516/: the values of RFC 7516 Appendix A.1,
#     RSA-OAEP with A256GCM, in VALUES.tsv, and its key as a1-key.json.
#
# Each VALUES.tsv has one row per value: its name, the section it is
# from, and the value. Octet arrays are written in Base64url, JSON with
# the RFC's display line breaks removed, and tokens as one line. Each
# directory's MANIFEST.tsv records the files and, in its header line, the
# SHA-256 of the RFC text they came from.
#
# Usage, from the package root:
#
#   curl -sSfo rfc7517.txt https://www.rfc-editor.org/rfc/rfc7517.txt
#   curl -sSfo rfc7516.txt https://www.rfc-editor.org/rfc/rfc7516.txt
#   Rscript tools/rfc7516-7517-fixtures.R rfc7517.txt rfc7516.txt
#
# The script is deterministic: running it again on the same RFC texts
# gives byte-identical fixtures. It needs zuutf and zujson, which zujose
# imports.

args <- commandArgs(trailingOnly = TRUE)
stopifnot(length(args) == 2L, all(file.exists(args)))

read_rfc <- function(path, number) {
  lines <- gsub("\f", "", readLines(path, warn = FALSE), fixed = TRUE)
  furniture <- grepl("\\[Page [0-9]+\\]$", lines) |
    grepl(sprintf("^RFC %d  ", number), lines)
  lines[!furniture]
}

# The lines of a section: from its heading to the next heading.
section <- function(lines, heading) {
  start <- which(startsWith(lines, heading))
  stopifnot(length(start) == 1L)
  rest <- seq(start + 1L, length(lines))
  end <- rest[grepl("^(Appendix )?[A-Z0-9]+(\\.[0-9]+)*\\.  ", lines[rest])]
  lines[seq(start, if (length(end)) end[[1]] - 1L else length(lines))]
}

b64 <- function(bytes) zuutf::base64_encode(bytes, url = TRUE, pad = FALSE)

# The n-th JSON array of octets in a section, as raw.
octets <- function(lines, n = 1L) {
  text <- paste(lines, collapse = " ")
  arrays <- regmatches(text, gregexpr("\\[[0-9, ]+\\]", text))[[1]]
  as.raw(as.integer(strsplit(gsub("[][ ]", "", arrays[[n]]), ",")[[1]]))
}

# The n-th indented JSON object in a section, with each line trimmed and
# the lines joined: a value's display line breaks are removed, and the
# spaces inside a value (a `kid`) are kept.
json_block <- function(lines, n = 1L) {
  starts <- which(grepl("^ +\\{", lines))
  i <- starts[[n]]
  depth <- 0L
  out <- character()
  repeat {
    line <- trimws(lines[[i]])
    out <- c(out, line)
    depth <- depth +
      lengths(regmatches(line, gregexpr("\\{", line))) -
      lengths(regmatches(line, gregexpr("\\}", line)))
    if (depth == 0L) {
      break
    }
    i <- i + 1L
  }
  json <- paste(out, collapse = "")
  zujson::json_parse(json)
  json
}

# The compact serialization after "The final result in this example".
final_token <- function(lines) {
  i <- grep("The final result in this example", lines)[[1]] + 1L
  out <- character()
  # The token's lines, which may be split by blank lines at a page break,
  # up to the first line of prose.
  while (i <= length(lines)) {
    line <- lines[[i]]
    if (grepl("^ +[A-Za-z0-9_.-]+$", line)) {
      out <- c(out, trimws(line))
    } else if (nzchar(trimws(line)) && length(out)) {
      break
    }
    i <- i + 1L
  }
  paste(out, collapse = "")
}

write_values <- function(dir, rows, files, rfc_path, number) {
  dir.create(dir, showWarnings = FALSE, recursive = TRUE)
  values <- do.call(rbind, lapply(rows, as.data.frame))
  utils::write.table(
    values,
    file.path(dir, "VALUES.tsv"),
    sep = "\t",
    quote = FALSE,
    row.names = FALSE
  )
  for (name in names(files)) {
    writeLines(files[[name]], file.path(dir, name), sep = "")
  }
  con <- file(file.path(dir, "MANIFEST.tsv"), "w")
  on.exit(close(con))
  writeLines(
    sprintf(
      paste0(
        "# RFC %d <https://www.rfc-editor.org/rfc/rfc%d.txt>, sha256 %s, ",
        "extracted by tools/rfc7516-7517-fixtures.R"
      ),
      number,
      number,
      tools::sha256sum(rfc_path)
    ),
    con
  )
  utils::write.table(
    data.frame(file = c(names(files), "VALUES.tsv")),
    con,
    sep = "\t",
    quote = FALSE,
    row.names = FALSE
  )
}

value <- function(name, sec, value) {
  list(name = name, section = sec, value = value)
}

# RFC 7517 ---------------------------------------------------------------

r7517 <- read_rfc(args[[1]], 7517L)
sets <- list(
  "jwks-a1.json" = json_block(section(r7517, "A.1.  ")),
  "jwks-a2.json" = json_block(section(r7517, "A.2.  ")),
  "jwks-a3.json" = json_block(section(r7517, "A.3.  "))
)
c1 <- section(r7517, "C.1.  ")
c2 <- section(r7517, "C.2.  ")
c4 <- section(r7517, "C.4.  ")
c8 <- section(r7517, "C.8.  ")
header_c2 <- json_block(c2)
rows <- list(
  value("plaintext", "C.1", b64(octets(c1))),
  value("header", "C.2", header_c2),
  value("p2s", "C.2", b64(octets(c2))),
  value("cek", "C.3", b64(octets(section(r7517, "C.3.  ")))),
  value("password", "C.4", b64(octets(c4, 1L))),
  value("salt", "C.4", b64(octets(c4, 2L))),
  value("derived_key", "C.4", b64(octets(c4, 3L))),
  value("encrypted_key", "C.5", b64(octets(section(r7517, "C.5.  ")))),
  value("iv", "C.6", b64(octets(section(r7517, "C.6.  ")))),
  # C.7 says the AAD is ASCII(BASE64URL(UTF8(header))), but its octets
  # are UTF8(header) itself; the check below holds it to that.
  value("header_octets", "C.7", b64(octets(section(r7517, "C.7.  ")))),
  value("ciphertext", "C.8", b64(octets(c8, 1L))),
  value("tag", "C.8", b64(octets(c8, 2L))),
  value("token", "C.9", final_token(section(r7517, "C.9.  ")))
)
parts <- strsplit(rows[[13]]$value, ".", fixed = TRUE)[[1]]
stopifnot(
  identical(parts[-1], vapply(rows[c(8, 9, 11, 12)], `[[`, "", "value")),
  identical(parts[[1]], rows[[10]]$value),
  identical(parts[[1]], b64(charToRaw(header_c2)))
)
write_values(
  file.path("tests", "testthat", "fixtures", "rfc7517"),
  rows,
  sets,
  args[[1]],
  7517L
)

# RFC 7516 ---------------------------------------------------------------

r7516 <- read_rfc(args[[2]], 7516L)
a1 <- section(r7516, "A.1.  ")
a13 <- section(r7516, "A.1.3.  ")
a16 <- section(r7516, "A.1.6.  ")
rows <- list(
  value("plaintext", "A.1", b64(octets(a1))),
  value("header", "A.1.1", json_block(section(r7516, "A.1.1.  "))),
  value("cek", "A.1.2", b64(octets(section(r7516, "A.1.2.  ")))),
  value("encrypted_key", "A.1.3", b64(octets(a13))),
  value("iv", "A.1.4", b64(octets(section(r7516, "A.1.4.  ")))),
  value("aad", "A.1.5", b64(octets(section(r7516, "A.1.5.  ")))),
  value("ciphertext", "A.1.6", b64(octets(a16, 1L))),
  value("tag", "A.1.6", b64(octets(a16, 2L))),
  value("token", "A.1.7", final_token(section(r7516, "A.1.7.  ")))
)
parts <- strsplit(rows[[9]]$value, ".", fixed = TRUE)[[1]]
stopifnot(
  identical(parts[-1], vapply(rows[c(4, 5, 7, 8)], `[[`, "", "value")),
  identical(b64(charToRaw(parts[[1]])), rows[[6]]$value)
)
write_values(
  file.path("tests", "testthat", "fixtures", "rfc7516"),
  rows,
  list("a1-key.json" = json_block(a13)),
  args[[2]],
  7516L
)
cat("wrote the RFC 7517 Appendix A and C, and RFC 7516 A.1, fixtures\n")
