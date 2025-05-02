from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class SeedEncryptor:
    def __init__(self, key):
        self.key = key.to_bytes(32, 'big') if isinstance(key, int) else key[:32]  # Truncate if too long

    def encrypt_seed(self, seed):
        """Encrypts the seed using AES-256 in CBC mode with a random IV."""
        seed_bytes = seed.to_bytes(8, 'little')

        iv = get_random_bytes(AES.block_size)

        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        padded_data = pad(seed_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)

        return iv + ciphertext

    def decrypt_seed(self, encrypted_data):
        """Decrypts the seed from combined IV + ciphertext."""
        iv = encrypted_data[:AES.block_size]
        ciphertext = encrypted_data[AES.block_size:]

        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        seed_bytes = unpad(decrypted_padded, AES.block_size)

        return int.from_bytes(seed_bytes, 'little')