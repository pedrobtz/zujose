# Stage 1 plan (scratch)

1. Fixtures: tools/rfc7520-fixtures.R extracts every serialization figure.
2. Tests first: b64url, limits, codec (fixtures, header rules, malformed
   corpus, limits before decoding with a mocked decoder), peek.
3. R/b64url.R, R/limits.R, R/codec.R, R/peek.R.
4. Imports zujson, zuutf; Remotes zuutf.
5. Re-check RFC 7520 citations in the roadmap against the fixtures.
