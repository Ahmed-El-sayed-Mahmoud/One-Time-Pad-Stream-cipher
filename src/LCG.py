class LCG:
    """
    Linear Congruential Generator (LCG) for generating pseudo-random numbers.
    """

    def __init__(self, a=7, b=0, m=127, seed=42):
        """
        Initialize the LCG with parameters a, b, m and seed.

        :param a: Multiplier
        :param b: Increment
        :param m: Modulus
        :param seed: Initial seed value
        """
        self.a = a
        self.b = b
        self.m = m
        self.state = seed

    def next(self):
        self.state = (self.a * self.state + self.b) % self.m
        return self.state

    def n_next(self, n):
        return [self.next() for _ in range(n)]
