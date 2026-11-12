# Measure what the differential fuzz cases reach in R/ (#97). Development
# only, never run at check time; fuzz.yaml runs it after replay.R. Needs
# covr, which is not in DESCRIPTION. Run from the package root:
#
#   Rscript tools/fuzz/reach.R [--out DIR] CASES.tsv ...
#
# Replays tools/fuzz/corpus/cases.tsv and every CASES.tsv through zujose
# under covr::file_coverage() over R/, prints the lines no case reached,
# file by file, as the gap list (also written to DIR/gaps.txt), and exits
# non-zero when the share of lines reached is under the floor in
# tools/fuzz/floor.txt. A gap is a path the fuzzer cannot report on: give
# gen.py a seed or a mutation that reaches it, then raise the floor.

args <- commandArgs(trailingOnly = TRUE)
out_dir <- tempdir()
if (length(args) >= 2L && args[[1]] == "--out") {
  out_dir <- args[[2]]
  args <- args[-(1:2)]
}
dir.create(out_dir, showWarnings = FALSE, recursive = TRUE)
corpus <- file.path("tools", "fuzz", "corpus", "cases.tsv")
paths <- normalizePath(unique(c(corpus[file.exists(corpus)], args)))
floor <- as.numeric(readLines(file.path("tools", "fuzz", "floor.txt"))[[1]])

# covr sources R/ into an environment and runs the driver there, so the
# calls in cases.R reach the traced functions.
driver <- tempfile(fileext = ".R")
writeLines(
  c(
    sprintf(
      "source(%s, local = TRUE)",
      deparse(normalizePath(
        file.path("tools", "fuzz", "cases.R")
      ))
    ),
    sprintf(
      "for (path in %s) run_cases(read_cases(path))",
      paste(deparse(paths), collapse = "")
    )
  ),
  driver
)
started <- Sys.time()
cov <- covr::file_coverage(
  list.files("R", pattern = "[.]R$", full.names = TRUE),
  driver
)
elapsed <- as.numeric(difftime(Sys.time(), started, units = "secs"))

reached <- covr::percent_coverage(cov)
gaps <- covr::zero_coverage(cov)
# Runs of consecutive lines, as "12-15, 20".
runs <- function(lines) {
  lines <- sort(unique(lines))
  starts <- lines[c(TRUE, diff(lines) != 1L)]
  ends <- lines[c(diff(lines) != 1L, TRUE)]
  paste(
    ifelse(starts == ends, starts, paste0(starts, "-", ends)),
    collapse = ", "
  )
}
report <- vapply(
  split(gaps$line, basename(gaps$filename)),
  runs,
  ""
)
report <- sprintf("%s: %s", names(report), report)
writeLines(report, file.path(out_dir, "gaps.txt"))

cat(sprintf(
  "reach.R: %d case files in %.0f s reach %.1f%% of R/ (floor %s%%); %d lines never reached\n",
  length(paths),
  elapsed,
  reached,
  format(floor),
  nrow(gaps)
))
cat(paste0("  ", report), sep = "\n")
if (reached < floor) {
  cat(sprintf(
    "reach.R: %.1f%% is under the floor of %s%% in tools/fuzz/floor.txt\n",
    reached,
    format(floor)
  ))
  quit(status = 1)
}
