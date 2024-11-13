from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

# Generate an 8-byte (64-bit) key for DES encryption
key = get_random_bytes(8)

# Create DES cipher in ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# Print the generated key (just for demonstration)
print("Generated Key:", key.hex())

# Plaintext (must be 8 bytes, or a multiple of 8 bytes for ECB mode)
plaintext = b'12345678'

# Encrypt the plaintext
ciphertext = cipher.encrypt(plaintext)
print("Encrypted Text:", ciphertext.hex())

# Decrypt the ciphertext
decrypted_text = cipher.decrypt(ciphertext)
print("Decrypted Text:", decrypted_text.decode())
