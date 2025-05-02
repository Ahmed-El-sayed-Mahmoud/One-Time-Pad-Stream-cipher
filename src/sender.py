import socket
import pickle
from stream_cipher import StreamCipher
from seed_encryption import SeedEncryptor
from key_exchange import DiffieHellman
from seed_auth import HMACAuth
from file_io import FileIO
from config import CONFIG
import os
import time


class SecureSender:
    def __init__(self):
        self.dh = DiffieHellman()
        self.seed = int.from_bytes(os.urandom(8), 'big')
        self.sock = None
        self.connection_timeout = 5  # seconds
        self.response_timeout = 10  # seconds
        self.max_retries = 3

    def connect(self):
        """Establish connection with retry logic"""
        for attempt in range(1, self.max_retries + 1):
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(self.connection_timeout)
                self.sock.connect(("localhost", 65432))
                self.sock.settimeout(self.response_timeout)
                print("Connected to receiver")
                return True
            except (ConnectionRefusedError, socket.timeout) as e:
                print(f"Connection attempt {attempt} failed: {str(e)}")
                if attempt < self.max_retries:
                    time.sleep(1)  # Wait before retrying
                continue
            except Exception as e:
                print(f"Unexpected connection error: {str(e)}")
                break
        return False

    def send_data(self, data_type, *data):
        """Send data with type identifier"""
        try:
            self.sock.sendall(pickle.dumps((data_type, *data)))
            return True
        except (socket.error, pickle.PicklingError) as e:
            print(f"Failed to send data: {str(e)}")
            return False

    def receive_data(self):
        """Receive and unpack data with proper error handling"""
        try:
            data = b''
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                try:
                    unpickled = pickle.loads(data)
                    return unpickled[0], unpickled[1:]
                except pickle.UnpicklingError:
                    continue  # Need more data

            raise ConnectionError("Connection closed by receiver")
        except socket.timeout:
            raise TimeoutError("No response received within timeout period")
        except Exception as e:
            raise ConnectionError(f"Error receiving data: {str(e)}")

    def perform_key_exchange(self):
        """Handle Diffie-Hellman key exchange"""
        if not self.send_data("DH_PUBLIC", self.dh.generate_public_key()):
            raise ConnectionError("Failed to send public key")
        print(f"Sent DH public key: {self.dh.public_key}")

        try:
            msg_type, (their_public_key,) = self.receive_data()
            if msg_type != "DH_PUBLIC":
                raise ValueError("Key exchange failed - invalid response")
            print(f"Received DH public key: {their_public_key}")
            return self.dh.generate_shared_secret(their_public_key)
        except ValueError as e:
            raise
        except Exception as e:
            raise ConnectionError(f"Key exchange failed: {str(e)}")

    def send_encrypted_seed(self, shared_key):
        """Encrypt and send the seed with HMAC"""
        encryptor = SeedEncryptor(shared_key)
        authenticator = HMACAuth(shared_key)

        encrypted_seed = encryptor.encrypt_seed(self.seed)
        seed_hmac = authenticator.compute_hmac(encrypted_seed)
        print(f"Encrypted seed: {encrypted_seed.hex()}")

        if not self.send_data("SEED", encrypted_seed, seed_hmac):
            raise ConnectionError("Failed to send encrypted seed")

    def send_encrypted_file(self):
        """Encrypt and send the file data"""
        try:
            plaintext = FileIO.read_input_file("input.txt")
            cipher = StreamCipher(seed=self.seed)
            ciphertext = cipher.encrypt(plaintext)

            if not self.send_data("DATA", ciphertext):
                raise ConnectionError("Failed to send encrypted data")
            print("File data sent successfully")
        except FileNotFoundError:
            raise FileNotFoundError("Input file not found")
        except Exception as e:
            raise ConnectionError(f"File encryption failed: {str(e)}")

    def initiate_communication(self):
        """Main communication workflow"""
        try:
            if not self.connect():
                raise ConnectionError("Failed to establish connection")

            shared_key = self.perform_key_exchange()
            self.send_encrypted_seed(shared_key)
            self.send_encrypted_file()

        except Exception as e:
            print(f"Communication failed: {str(e)}")
        finally:
            if self.sock:
                self.sock.close()
                print("Connection closed")


if __name__ == "__main__":
    sender = SecureSender()
    sender.initiate_communication()