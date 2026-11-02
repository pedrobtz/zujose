# Stage 4 plan (scratch)

1. verify_jws(): jose_verify() body, called by jose_jwt_decode() with its own call.
2. abort_claim() and the six claim leaf classes.
3. Tests first: RFC 7519 3.1 and 6.1, each claim check, typ, nesting,
   decoder, and the jose oracle under skip_if_not_installed().
4. R/jwt.R: jose_jwt_encode(), jose_jwt_decode(), jose_jwt_decoder().
5. Suggests: jose. The stage is full: the nosuggests leg runs.
