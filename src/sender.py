from file_io import FileIO
from src.seed_auth import HMACAuth
from stream_cipher import StreamCipher
from seed_encryption import SeedEncryption
from communication import Communication
from LCG import LCG
from key_exchange import DiffieHellman
import random


class Sender:
    def __init__(self):
        """
        Initialize the Sender with LCG parameters and other components.
        """
        self.lcg = LCG()
        self.file_io = FileIO()
        self.hmac_auth = HMACAuth()
        self.seed_encryption = SeedEncryption()
        self.communication = Communication()
        self.diffie_hellman = DiffieHellman()
        self.stream_cipher = StreamCipher()

    def generate_seed(self):
        """
        Generate a random seed using LCG parameters.
        """
        # Generate a random seed
        seed = random.randint(0, 255)
        return seed

    def send_seed(self, seed):
        """
        Send the seed to the receiver after encrypting it.

        :param seed: Seed value to be sent
        """
        # Encrypt the seed
        encrypted_seed = self.seed_encryption.encrypt_seed(seed)

        # Send the encrypted seed
        self.communication.send(encrypted_seed)

    def send_public_key(self):
        """
        Send the public key to the receiver.
        """
        public_key = self.diffie_hellman.generate_public_key()
        self.communication.send(public_key)

    def send_encrypted_message(self, message):
        """
        Encrypt and send the message to the receiver.

        :param message: Message to be sent
        """
        # Encrypt the message using the stream cipher
        encrypted_message = self.stream_cipher.encrypt(message)

        # Send the encrypted message
        self.communication.send(encrypted_message)

    def send_hmac(self, message):
        """
        Send the HMAC of the message to the receiver.

        :param message: Message to be authenticated
        """
        # Generate HMAC for the message
        hmac = self.hmac_auth.compute_hmac(message)

        # Send the HMAC
        self.communication.send(hmac)
