import math

# Class Entropy to calculate URL entropy.
# Entropy is often described as a measure of randomness. Malicious URLs
# will typically have a higher entropy and randomness.
# Entropy is calculated using Shannon Entropy -
# https://en.wiktionary.org/wiki/Shannon_entropy
# http://pythonfiddle.com/shannon-entropy-calculation/


class Entropy:
    def __init__(self, data):
        self.data = data

    def range_bytes(): return range(256)

    def range_printable(self): return (ord(c) for c in self.data.printable)

    def H(self, data, iterator=range_bytes):
        if not data:
            return 0
        entropy = 0
        for x in iterator():
            p_x = float(data.count(chr(x)))/len(data)
            if p_x > 0:
                entropy += - p_x*math.log(p_x, 2)
                entropy = float(format(entropy, '.5f'))
        return entropy
