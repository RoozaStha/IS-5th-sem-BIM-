import random
from sympy import isprime

# Function to generate keys for RSA
def generate_keys(bits=8):
    # Step 1: Choose two distinct prime numbers p and q
    p = generate_prime(bits)
    q = generate_prime(bits)
    
    # Step 2: Compute n = p * q
    n = p * q
    
    # Step 3: Compute Euler's totient function phi(n) = (p-1) * (q-1)
    phi_n = (p - 1) * (q - 1)
    
    # Step 4: Choose an integer e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1
    e = choose_e(phi_n)
    
    # Step 5: Compute d such that d * e ≡ 1 (mod phi(n))
    d = mod_inverse(e, phi_n)
    
    # Public key is (e, n), private key is (d, n)
    public_key = (e, n)
    private_key = (d, n)
    
    return public_key, private_key

# Function to check if a number is prime
def generate_prime(bits):
    while True:
        prime_candidate = random.getrandbits(bits)
        if isprime(prime_candidate):
            return prime_candidate

# Function to choose a valid e
def choose_e(phi_n):
    e = random.randrange(2, phi_n)
    while gcd(e, phi_n) != 1:
        e = random.randrange(2, phi_n)
    return e

# Function to compute gcd of two numbers
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Function to compute the modular inverse
def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

# Function to encrypt the message using the public key
def encrypt(message, public_key):
    e, n = public_key
    # Convert message to integers
    message_int = [ord(c) for c in message]
    # Encrypt each character
    ciphertext = [pow(m, e, n) for m in message_int]
    return ciphertext

# Function to decrypt the message using the private key
def decrypt(ciphertext, private_key):
    d, n = private_key
    # Decrypt each character
    decrypted_int = [pow(c, d, n) for c in ciphertext]
    # Convert integers back to characters
    message = ''.join(chr(i) for i in decrypted_int)
    return message

# Main execution
if __name__ == "__main__":
    # Generate public and private keys
    public_key, private_key = generate_keys(bits=8)  # 8-bit primes for simplicity
    
    print("Public Key:", public_key)
    print("Private Key:", private_key)
    
    # Input message to encrypt
    message = input("Enter the message to encrypt: ")
    
    # Encrypt the message
    encrypted_message = encrypt(message, public_key)
    print("Encrypted Message:", encrypted_message)
    
    # Decrypt the message
    decrypted_message = decrypt(encrypted_message, private_key)
    print("Decrypted Message:", decrypted_message)
