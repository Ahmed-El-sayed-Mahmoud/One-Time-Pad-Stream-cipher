import socket
import pickle
from io import BytesIO

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
        self.buffer = b''  # Buffer for incoming data

    def accept_connection(self):
        self.conn, self.addr = self.sock.accept()
        print(f"Connected by {self.addr}")

    def receive_data(self):
        """Receive and unpack data with proper buffering"""
        while True:
            if self.buffer:
                buffer_stream = BytesIO(self.buffer)
                unpickler = pickle.Unpickler(buffer_stream)
                try:
                    data = unpickler.load()
                    bytes_processed = buffer_stream.tell()
                    self.buffer = self.buffer[bytes_processed:]
                    return data[0], data[1:]
                except Exception as e:
                    # Need more data to complete the unpickling
                    pass

            # Receive more data from the connection
            chunk = self.conn.recv(4096)
            if not chunk:
                if self.buffer:
                    raise pickle.UnpicklingError("Incomplete data received")
                else:
                    raise ConnectionError("Connection closed by sender")
            self.buffer += chunk

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

        # Step 4: Receive and decrypt data chunks
        cipher = StreamCipher(seed=seed)
        ciphertext = b''
        try:
            while True:
                msg_type, (chunk,) = self.receive_data()
                if msg_type != "DATA":
                    raise ValueError(f"Unexpected message type: {msg_type}")
                ciphertext += chunk
        except (ConnectionError, pickle.UnpicklingError):
            # Connection closed normally after all data chunks
            pass

        print("RECEIVED CIPHER", ciphertext)
        plaintext = cipher.decrypt(ciphertext)
        print(f"Decrypted data: {plaintext}")
        FileIO.write_text_file(plaintext, "output.txt")
        print("Received and decrypted data")

        self.conn.close()


if __name__ == "__main__":
    receiver = Receiver()
    receiver.establish_connection()