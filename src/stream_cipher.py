import numpy as np
from LCG import LCG


class StreamCipher:
    """
    Stream Cipher using Linear Congruential Generator (LCG) for pseudo-random number generation.
    """

    def __init__(self, a=7, b=0, m=127, seed=42):
        """
        Initialize the Stream Cipher with LCG parameters.

        :param a: Multiplier
        :param b: Increment
        :param m: Modulus
        :param seed: Initial seed value
        """
        self.lcg = LCG(a, b, m, seed)

    def encrypt(self, plaintext):
        """
        :param file_name: Name of the input file
        :return: Ciphertext as a list of integers
        """

        ciphertext = np.bitwise_xor(plaintext, self.lcg.n_next(len(plaintext)))
        return ciphertext
