from config import CONFIG


class LCG:
    """
    Linear Congruential Generator (LCG) for generating pseudo-random numbers.
    """

    def __init__(self, a=CONFIG["LCG"]["a"], b=CONFIG["LCG"]["b"], m=CONFIG["LCG"]["m"], seed=CONFIG["LCG"]["seed"]):
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
