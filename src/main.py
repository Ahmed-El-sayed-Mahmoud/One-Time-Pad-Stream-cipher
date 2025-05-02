from sender import Sender
from receiver import Receiver

sender = Sender()
receiver = Receiver()
seed = sender.generate_seed()
sender.send_seed(seed)
receiver.receive_seed()
sender.send_public_key()
receiver.receive_public_key()

sender.send_encrypted_message("Hello, World!")
encrypted_msg = receiver.receive_encrypted_message()
sender.send_hmac("Hello, World!")
hmac = receiver.receive_hmac()

decrypted_msg = receiver.decrypt_message(encrypted_msg)
print(f"Decrypted message: {decrypted_msg}")
print(f"Received HMAC: {hmac}")
receiver.verify_hmac(decrypted_msg, hmac)
print("HMAC verified successfully.")
