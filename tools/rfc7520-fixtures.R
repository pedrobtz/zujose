# Extract the JWS and JWE serializations of RFC 7520 (the JOSE cookbook)
# into tests/testthat/fixtures/rfc7520/, one file per figure, with a
# MANIFEST.tsv recording each figure's number and section; and the six keys
# of RFC 7520 §3 into key-NNN.json files, with KEYS.tsv.
#
# Usage, from the package root:
#
#   curl -sSfo rfc7520.txt https://www.rfc-editor.org/rfc/rfc7520.txt
#   Rscript tools/rfc7520-fixtures.R rfc7520.txt
#
# The script is deterministic: running it again on the same RFC text gives
# byte-identical fixtures. The SHA-256 of the RFC text it read is written to
# the manifest's header line.

args <- commandArgs(trailingOnly = TRUE)
stopifnot(length(args) == 1L, file.exists(args[[1]]))
rfc_path <- args[[1]]
out_dir <- file.path("tests", "testthat", "fixtures", "rfc7520")

lines <- readLines(rfc_path, warn = FALSE)
lines <- gsub("\f", "", lines, fixed = TRUE)

# Page furniture: footer, header, and the blank lines around them are
# harmless, but the footer and header lines must go.
furniture <- grepl("^Miller +Informational +\\[Page [0-9]+\\]$", lines) |
  grepl("^RFC 7520 +JOSE Cookbook +May 2015$", lines)
lines <- lines[!furniture]

caption_re <- "^ +Figure ([0-9]+): (General |Flattened )?(JWS|JWE) (Compact|JSON) Serialization$"
section_re <- "^([0-9]+(\\.[0-9]+)*)\\.  (.*)$"

captions <- grep(caption_re, lines)
sections <- grep(section_re, lines)

rows <- list()
for (at in captions) {
  m <- regmatches(lines[at], regexec(caption_re, lines[at]))[[1]]
  figure <- as.integer(m[[2]])
  type <- m[[4]]

  # The figure body is the block above the caption, back to the prose line
  # introducing it, which ends with a colon.
  i <- at - 1L
  body <- character()
  while (i > 0L && !grepl(":\\s*$", lines[[i]])) {
    body <- c(lines[[i]], body)
    i <- i - 1L
  }
  token <- gsub("\\s+", "", paste(body, collapse = ""))
  stopifnot(nzchar(token))

  # The serialization comes from the token, not the caption: Figure 41 is
  # captioned "General JWS JSON Serialization" but is compact.
  serialization <- if (!startsWith(token, "{")) {
    "compact"
  } else if (grepl("\"(signatures|recipients)\":", token)) {
    "general"
  } else {
    "flattened"
  }

  sec_line <- lines[[max(sections[sections < at])]]
  section <- regmatches(sec_line, regexec(section_re, sec_line))[[1]][[2]]

  file <- sprintf("fig-%03d.txt", figure)
  rows[[length(rows) + 1L]] <- data.frame(
    file = file,
    figure = figure,
    section = section,
    type = type,
    serialization = serialization
  )
  writeLines(token, file.path(out_dir, file), sep = "")
}

manifest <- do.call(rbind, rows)
sha <- tools::sha256sum(rfc_path)
con <- file(file.path(out_dir, "MANIFEST.tsv"), "w")
writeLines(
  sprintf(
    "# RFC 7520 <https://www.rfc-editor.org/rfc/rfc7520.txt>, sha256 %s, extracted by tools/rfc7520-fixtures.R",
    unname(sha)
  ),
  con
)
utils::write.table(manifest, con, sep = "\t", quote = FALSE, row.names = FALSE)
close(con)
cat(nrow(manifest), "fixtures written to", out_dir, "\n")

# The keys of §3: each figure body is a JSON object, from its "{" line to
# the caption.
key_caption_re <- "^ +Figure ([0-9]+): (.* Key)$"
key_rows <- list()
for (at in grep(key_caption_re, lines)) {
  m <- regmatches(lines[at], regexec(key_caption_re, lines[at]))[[1]]
  figure <- as.integer(m[[2]])
  i <- at - 1L
  while (!grepl("^ +\\{\\s*$", lines[[i]])) {
    i <- i - 1L
  }
  jwk <- gsub("\\s+", "", paste(lines[i:(at - 1L)], collapse = ""))
  sec_line <- lines[[max(sections[sections < at])]]
  section <- regmatches(sec_line, regexec(section_re, sec_line))[[1]][[2]]
  file <- sprintf("key-%03d.json", figure)
  key_rows[[length(key_rows) + 1L]] <- data.frame(
    file = file,
    figure = figure,
    section = section,
    description = m[[3]]
  )
  writeLines(jwk, file.path(out_dir, file), sep = "")
}
keys <- do.call(rbind, key_rows)
con <- file(file.path(out_dir, "KEYS.tsv"), "w")
writeLines(
  sprintf(
    "# RFC 7520 <https://www.rfc-editor.org/rfc/rfc7520.txt>, sha256 %s, extracted by tools/rfc7520-fixtures.R",
    unname(sha)
  ),
  con
)
utils::write.table(keys, con, sep = "\t", quote = FALSE, row.names = FALSE)
close(con)
cat(nrow(keys), "keys written to", out_dir, "\n")

