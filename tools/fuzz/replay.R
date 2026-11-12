# Replay the differential fuzz cases through zujose and compare its
# verdicts with jwcrypto's and PyJWT's (#96). Development only, never run
# at check time; fuzz.yaml runs it weekly. Run from the package root:
#
#   Rscript tools/fuzz/replay.R [--out DIR] CASES.tsv ...
#
# Each CASES.tsv is what tools/fuzz/gen.py wrote, with keys.tsv beside
# it; tools/fuzz/corpus/cases.tsv, the cases that once disagreed, is
# always replayed first. A case disagrees with a reference when their
# verdicts differ, or when both accept with different payloads (JWS and
# JWE; a JWT's claims are not compared). A zujose failure that is not a
# zujose_error is an `error` verdict, which disagrees with every
# reference.
#
# tools/fuzz/allow.tsv lists the deliberate divergences, each with its
# reason; its `strict` rows are also rules zujose must keep on every case
# they match (see its header). Exits non-zero on any disagreement it does
# not excuse and on any broken rule, after writing those cases to
# DIR/disagreements.tsv in the cases format: once fixed or allow-listed,
# add them to tools/fuzz/corpus/cases.tsv so every later run replays them.

pkgload::load_all(quiet = TRUE)
source(file.path("tools", "fuzz", "cases.R"))

args <- commandArgs(trailingOnly = TRUE)
out_dir <- tempdir()
if (length(args) >= 2L && args[[1]] == "--out") {
  out_dir <- args[[2]]
  args <- args[-(1:2)]
}
dir.create(out_dir, showWarnings = FALSE, recursive = TRUE)
corpus <- file.path("tools", "fuzz", "corpus", "cases.tsv")
paths <- unique(c(corpus[file.exists(corpus)], args))

allow <- utils::read.delim(
  file.path("tools", "fuzz", "allow.tsv"),
  colClasses = "character",
  quote = "",
  comment.char = "#",
  encoding = "UTF-8"
)
stopifnot(
  all(nzchar(allow$reason)),
  all(allow$strict %in% c("yes", "no")),
  all(c(allow$zujose, allow$verdict) %in% c("accept", "reject"))
)

started <- Sys.time()
cases <- do.call(
  rbind,
  lapply(paths, function(path) {
    run_cases(read_cases(path))
  })
)
elapsed <- as.numeric(difftime(Sys.time(), started, units = "secs"))

# hits[k, i]: case k matches allow.tsv row i by kind, seed and mutation.
hits <- vapply(
  seq_len(nrow(allow)),
  function(i) {
    (allow$kind[[i]] == "*" | cases$kind == allow$kind[[i]]) &
      grepl(allow$seed[[i]], cases$seed, perl = TRUE) &
      grepl(allow$mutation[[i]], cases$mutation, perl = TRUE)
  },
  logical(nrow(cases))
)
hits <- matrix(hits, nrow = nrow(cases))

# Disagreements, one row per case and reference, with the allow.tsv row
# that excuses each (NA if none).
found <- list()
for (ref in c("jwcrypto", "pyjwt")) {
  verdict <- cases[[ref]]
  payload <- cases[[paste0(ref, "_payload")]]
  differ <- verdict != "na" &
    (cases$zujose != verdict |
      (cases$kind != "jwt" &
        verdict == "accept" &
        cases$zujose_payload != payload))
  for (k in which(differ)) {
    excuse <- which(
      hits[k, ] &
        allow$reference %in% c(ref, "*") &
        allow$zujose == cases$zujose[[k]] &
        allow$verdict == verdict[[k]]
    )
    found[[length(found) + 1L]] <- data.frame(
      index = k,
      reference = ref,
      allow = if (length(excuse)) excuse[[1]] else NA_integer_
    )
  }
}
found <- do.call(
  rbind,
  c(
    list(data.frame(
      index = integer(),
      reference = character(),
      allow = integer()
    )),
    found
  )
)
new <- found[is.na(found$allow), ]

# Broken rules: a strict row's verdict not given on a case it matches.
broken <- list()
for (i in which(allow$strict == "yes")) {
  for (k in which(hits[, i] & cases$zujose != allow$zujose[[i]])) {
    broken[[length(broken) + 1L]] <- data.frame(index = k, rule = i)
  }
}
broken <- do.call(
  rbind,
  c(list(data.frame(index = integer(), rule = integer())), broken)
)

used <- tabulate(found$allow[!is.na(found$allow)], nrow(allow))
kinds <- table(cases$kind)
cat(sprintf(
  paste0(
    "replay.R: %d cases (%s) in %.0f s; %d disagreements, ",
    "%d allow-listed, %d new; %d broken rules\n"
  ),
  nrow(cases),
  paste(sprintf("%s %d", names(kinds), kinds), collapse = ", "),
  elapsed,
  nrow(found),
  sum(!is.na(found$allow)),
  nrow(new),
  nrow(broken)
))
for (i in which(used > 0)) {
  cat(sprintf(
    "  allow.tsv row %d (%s, %s): %d\n",
    i,
    allow$reference[[i]],
    allow$mutation[[i]],
    used[[i]]
  ))
}
if (any(used == 0)) {
  cat(sprintf(
    "  allow.tsv rows that excused nothing this run: %s\n",
    paste(which(used == 0), collapse = ", ")
  ))
}

describe <- function(case) {
  sprintf(
    "%s %s %s [%s]: zujose %s %s",
    case$id,
    case$kind,
    case$seed,
    case$mutation,
    case$zujose,
    case$zujose_class
  )
}
for (k in seq_len(nrow(new))) {
  case <- cases[new$index[[k]], ]
  ref <- new$reference[[k]]
  cat(sprintf(
    "DISAGREE %s; %s %s %s\n",
    describe(case),
    ref,
    case[[ref]],
    case$note
  ))
}
for (k in seq_len(nrow(broken))) {
  rule <- broken$rule[[k]]
  cat(sprintf(
    "BROKEN allow.tsv row %d (%s must %s): %s\n",
    rule,
    allow$mutation[[rule]],
    allow$zujose[[rule]],
    describe(cases[broken$index[[k]], ])
  ))
}

report <- cases[
  sort(unique(c(new$index, broken$index))),
  setdiff(names(cases), c("source", "zujose", "zujose_payload", "zujose_class"))
]
utils::write.table(
  report,
  file.path(out_dir, "disagreements.tsv"),
  sep = "\t",
  quote = FALSE,
  row.names = FALSE,
  fileEncoding = "UTF-8"
)
if (nrow(report)) {
  cat(sprintf(
    "replay.R: wrote %d cases to %s\n",
    nrow(report),
    file.path(out_dir, "disagreements.tsv")
  ))
  quit(status = 1)
}
