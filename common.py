# https: // stackoverflow.com/a/6822773
# s = [s0, s1, s2, s3, s4] -> [(s0,s1), (s1, s2), (s2, s3), (s3, s4)]
def pairwise(seq):
    window_size = 2
    for i in range(len(seq) - window_size + 1):
        yield (seq[i: i + window_size])


# A hexadecimal string, `0x` prepending it
# The reason why the specs needs it is because of:https://ethereum.org/en/developers/docs/apis/json-rpc/#unformatted-data-encoding
hex_str = str


def bytes_from_hex(hex_str: hex_str):
    if hex_str.startswith("0x"):
        # Skip the first two characters
        return bytes.fromhex(hex_str[2:])
    return bytes.fromhex(hex_str)


def bytes_to_hex(byts: bytes):
    return "0x" + byts.hex()
