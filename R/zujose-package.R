#' @details
#' Start with the Get started article, at
#' <https://pedrobtz.github.io/zujose/articles/zujose.html>. The main
#' functions are:
#'
#' * JWT: [jwt_encode()], [jwt_decode()], [jwt_decoder()].
#' * JWS: [jws_sign()], [jws_verify()].
#' * JWE: [jwe_encrypt()], [jwe_decrypt()].
#' * Keys: [jwk_oct()], [jwk_generate()], [as_jwk()],
#'   [jwk_set()], [as_jwk_set()], [jwk_json()], [jwk_pem()].
#' * Inspection: [jose_peek()], [zujose_info()].
#'
#' zujose never fetches anything: keys come only from the caller, as a
#' key, a key set, or a function that returns one (a resolver).
#'
#' @inheritSection jwk_oct Secrets in memory
#' @keywords internal
#' @examples
#' key <- jwk_generate("oct", alg = "HS256")
#' jwt <- jwt_encode(list(sub = "user-1"), key, expires_in = 3600)
#' jwt_decode(jwt, key, algorithms = "HS256")$sub
"_PACKAGE"

## usethis namespace: start
## usethis namespace: end
NULL
