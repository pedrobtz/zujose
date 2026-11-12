# jose_limits() prints every limit

    Code
      print(jose_limits(signatures = 2))
    Output
      <jose_limits>
        token      2,097,152
        header     16,384
        payload    1,048,576
        signatures 2
        recipients 16
        keys       16
        p2c        600,000

# jose_limits() prints the same under a comma decimal mark

    Code
      print(jose_limits(token = Inf))
    Output
      <jose_limits>
        token      Inf
        header     16,384
        payload    1,048,576
        signatures 16
        recipients 16
        keys       16
        p2c        600,000

