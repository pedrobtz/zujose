# Small helpers used throughout the package.

`%||%` <- function(x, y) if (is.null(x)) y else x

is_string <- function(x) {
  is.character(x) && length(x) == 1L && !is.na(x)
}

# Exact member lookup: `$` would partially match.
member <- function(x, name) {
  if (name %in% names(x)) x[[name]] else NULL
}

# A named empty list, which zujson writes as `{}`, not `[]`.
empty_object <- function() {
  stats::setNames(list(), character())
}
