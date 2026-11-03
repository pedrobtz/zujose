# Base64url without padding, decoded strictly and canonically (design §8.1).
#
# zuutf's strict mode requires padding, which JOSE forbids, so the alphabet
# and length are checked here, padding is added, and zuutf then rejects
# whitespace and non-zero trailing bits. Every value therefore has exactly
# one accepted encoding.

b64url_decode <- function(x, what, call = NULL) {
  n <- nchar(x, type = "bytes")
  if (!grepl("^[A-Za-z0-9_-]*$", x) || n %% 4L == 1L) {
    abort_zujose(
      "parse",
      sprintf("The %s is not unpadded Base64url.", what),
      call = call
    )
  }
  if (n == 0L) {
    return(raw())
  }
  padded <- paste0(x, strrep("=", (4L - n %% 4L) %% 4L))
  tryCatch(
    zuutf::base64_decode(padded, url = TRUE, forgiving = FALSE),
    zuutf_error = function(e) {
      abort_zujose(
        "parse",
        sprintf("The %s is not canonical Base64url.", what),
        call = call
      )
    }
  )
}

b64url_encode <- function(x) {
  if (length(x) == 0L) {
    return("")
  }
  zuutf::base64_encode(x, url = TRUE, pad = FALSE)
}

# The longest unpadded Base64url text that decodes to at most `bytes` bytes.
b64url_max_chars <- function(bytes) {
  if (is.infinite(bytes)) {
    return(Inf)
  }
  ceiling(bytes / 3) * 4
}
