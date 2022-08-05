# https: // stackoverflow.com/a/6822773
# s = [s0, s1, s2, s3, s4] -> [(s0,s1), (s1, s2), (s2, s3), (s3, s4)]
def pairwise(seq):
    window_size = 2
    for i in range(len(seq) - window_size + 1):
        yield (seq[i: i + window_size])


# A hexadecimal string, without `0x` prepending it
hex_str = str
# TODO: This doesn't match the specs. The Json file has prepended 0x
# TODO: Internally in the cryptography, we do not use 0x, though when we give it to the frontend
# TODO we need to add it. The reason why the specs needs it is because of:https://ethereum.org/en/developers/docs/apis/json-rpc/#unformatted-data-encoding
