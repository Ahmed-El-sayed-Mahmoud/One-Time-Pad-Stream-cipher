import numpy as np

from file_io import FileIO
from src.seed_auth import HMACAuth
from stream_cipher import StreamCipher
from seed_encryption import SeedEncryption
from communication import Communication
from LCG import LCG
from key_exchange import DiffieHellman


class Receiver:
    def __init__(self):
        self.communication = Communication()
        self.file_io = FileIO()
        self.seed_encryption = SeedEncryption()
        self.hmac_auth = HMACAuth()
        self.diffie_hellman = DiffieHellman()
        self.lcg = LCG()

    def receive_seed(self):
        """
        Receive the encrypted seed from the sender and decrypt it.
        """
        encrypted_seed = self.communication.receive()
        decrypted_seed = self.seed_encryption.decrypt_seed(encrypted_seed)
        return decrypted_seed

    def receive_public_key(self):
        """
        Receive the public key from the sender.
        """
        public_key = self.communication.receive()
        return public_key


    def send_public_key(self):
        """
        Send the public key to the sender.
        """
        public_key = self.diffie_hellman.generate_public_key()
        self.communication.send(public_key)

    def receive_encrypted_message(self):
        """
        Receive the encrypted message from the sender.
        """
        encrypted_message = self.communication.receive()
        return encrypted_message

    def receive_hmac(self):
        """
        Receive the HMAC from the sender.
        """
        hmac = self.communication.receive()
        return hmac

    def verify_hmac(self, message, hmac):
        """
        :param message:
        :param hmac:
        :return:
        """
        # Verify the HMAC of the received message
        return self.hmac_auth.verify_hmac(message, hmac)

    def decrypt_message(self, encrypted_message):
        """
        Decrypt the encrypted message using the LCG to generate a keystream.
        """
        keystream = self.lcg.generate_sequence(len(encrypted_message))
        decrypted_message = np.bitwise_xor(encrypted_message, keystream)
        print("Decrypted message:", decrypted_message)
        return decrypted_message
