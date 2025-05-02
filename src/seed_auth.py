import hmac
import hashlib


class HMACAuth:

    def __init__(self, key):
        """
        Initialize the HMACAuth class.
        """
        self.key = key.to_bytes(32, 'big')  # Ensure the key is 32 bytes long

    def compute_hmac(self, data):
        return hmac.new(self.key, data, hashlib.sha256).digest()

    def verify_hmac(self, data, mac):
        expected_mac = self.compute_hmac(data)
        return hmac.compare_digest(mac, expected_mac)
