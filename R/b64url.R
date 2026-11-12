# Base64url without padding, decoded strictly and canonically (design §8.1,
# D6): zuutf's strict unpadded mode refuses padding, whitespace, the
# standard alphabet, a one-character final quantum and non-zero trailing
# bits, so every value has exactly one accepted encoding.

b64url_decode <- function(x, what, call = NULL) {
  tryCatch(
    zuutf::base64_decode(x, url = TRUE, forgiving = FALSE, pad = FALSE),
    zuutf_error = function(e) {
      abort_zujose(
        "parse",
        sprintf("The %s is not canonical unpadded Base64url.", what),
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

# The longest unpadded Base64url text that decodes to at most `bytes` bytes:
# exactly the encoded length of `bytes` bytes, as decoding is strict.
b64url_max_chars <- function(bytes) {
  if (is.infinite(bytes)) {
    return(Inf)
  }
  ceiling(4 * bytes / 3)
}
