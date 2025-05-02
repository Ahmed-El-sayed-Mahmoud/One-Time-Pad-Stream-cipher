from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class SeedEncryption:
    def __init__(self, key: bytes):
        # AES key must be 16, 24, or 32 bytes long (128, 192, or 256 bits)
        self.key = key

    def encrypt_seed(self, seed_bytes: bytes):
        iv = get_random_bytes(16)  # Initialization Vector (16 bytes for AES)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_seed = cipher.encrypt(pad(seed_bytes, AES.block_size))
        return iv + encrypted_seed  # Prepend IV for use during decryption

    def decrypt_seed(self, encrypted_seed: bytes):
        iv = encrypted_seed[:16]
        ciphertext = encrypted_seed[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_seed = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_seed
