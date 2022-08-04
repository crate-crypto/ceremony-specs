# https: // stackoverflow.com/a/6822773
# s = [s0, s1, s2, s3, s4] -> [(s0,s1), (s1, s2), (s2, s3), (s3, s4)]
def pairwise(seq):
    window_size = 2
    for i in range(len(seq) - window_size + 1):
        yield (seq[i: i + window_size])
