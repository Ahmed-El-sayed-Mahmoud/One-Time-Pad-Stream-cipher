import socket
import pickle

from websockets import SecurityError

from stream_cipher import StreamCipher
from seed_encryption import SeedEncryptor
from key_exchange import DiffieHellman
from seed_auth import HMACAuth
from file_io import FileIO
from config import CONFIG


class Receiver:
    def __init__(self):
        self.dh = DiffieHellman()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("localhost", 65432))
        self.sock.listen()

    def accept_connection(self):
        self.conn, self.addr = self.sock.accept()
        print(f"Connected by {self.addr}")

    def receive_data(self):
        """Receive and unpack data"""
        data = pickle.loads(self.conn.recv(4096))
        return data[0], data[1:]

    def send_data(self, data_type, *data):
        """Send data with type identifier"""
        self.conn.sendall(pickle.dumps((data_type, *data)))

    def establish_connection(self):
        self.accept_connection()

        # Step 1: Receive sender's public key
        msg_type, (their_public_key,) = self.receive_data()
        if msg_type != "DH_PUBLIC":
            raise ValueError("Key exchange failed")
        print(f"Received DH public key: {their_public_key}")

        # Step 2: Send our public key
        self.send_data("DH_PUBLIC", self.dh.generate_public_key())
        print(f"Sent DH public key: {self.dh.public_key}")

        # Generate shared key
        shared_key = self.dh.generate_shared_secret(their_public_key)

        # Step 3: Receive and verify seed
        msg_type, (encrypted_seed, seed_hmac) = self.receive_data()
        if msg_type != "SEED":
            raise ValueError("Seed transmission failed")

        authenticator = HMACAuth(shared_key)
        if not authenticator.verify_hmac(encrypted_seed, seed_hmac):
            raise ValueError("HMAC verification failed")

        encryptor = SeedEncryptor(shared_key)
        print("Received encrypted seed", encrypted_seed)
        seed = encryptor.decrypt_seed(encrypted_seed)
        print(f"Decrypted seed: {seed}")

        # Step 4: Receive and decrypt data
        cipher = StreamCipher(seed=seed)
        msg_type, (ciphertext,) = self.receive_data()
        print("RECEIVED CIPHER", ciphertext)
        if msg_type != "DATA":
            raise ValueError("Data transmission failed")

        plaintext = cipher.decrypt(ciphertext)
        print(f"Decrypted data: {plaintext}")
        FileIO.write_text_file(plaintext, "output.txt")
        print("Received and decrypted data")

        self.conn.close()


if __name__ == "__main__":
    receiver = Receiver()
    receiver.establish_connection()