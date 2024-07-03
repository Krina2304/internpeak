from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

# AES encryption function
def encrypt(message, key):
    # Ensure the message is a multiple of 16 bytes (AES block size)
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    
    # Generate an AES cipher with CBC mode
    iv = b'1234567890123456'  # Initialization Vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the padded message
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    # Return base64 encoded ciphertext and IV for storage or transmission
    return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()

# AES decryption function
def decrypt(ciphertext, key, iv):
    # Decode base64 encoded ciphertext and IV
    ciphertext = base64.b64decode(ciphertext)
    iv = base64.b64decode(iv)
    
    # Create AES cipher with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    
    # Return the decrypted message as a string
    return message.decode()

if __name__ == "__main__":
    # Example usage:
    message = "Hello, World!"
    key = b'sixteenbyteslong'
    
    # Encrypt the message
    ciphertext, iv = encrypt(message, key)
    print(f"Ciphertext: {ciphertext}")
    print(f"IV: {iv}")
    
    # Decrypt the ciphertext
    decrypted_message = decrypt(ciphertext, key, iv)
    print(f"Decrypted message: {decrypted_message}")
