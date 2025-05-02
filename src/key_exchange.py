import random


class DiffieHellman:
    def __init__(self):
        self.p = 23  # A prime number
        self.g = 5  # A primitive root modulo p
        self.private_key = random.randint(1, 22)
        self.public_key = None

    def generate_public_key(self):
        """
        Generate the public key using the other party's public key.
        :return: Public key
        """
        self.public_key = (self.g ** self.private_key) % self.p
        return self.public_key

    def generate_shared_secret(self, other_public_key):
        """
        Generate the shared secret using the other party's public key.
        :param other_public_key: Public key of the other party
        :return: Shared secret
        """
        return (other_public_key ** self.private_key) % self.p
