# non-zero trailing bits in any part fail at token level

    Code
      jose_parse(token, jose_limits())
    Condition
      Error:
      ! The payload is not canonical unpadded Base64url.

# a token that is not valid UTF-8 is refused without warnings

    Code
      jose_peek(token)
    Condition
      Error in `jose_peek()`:
      ! The token is not valid UTF-8 text.

