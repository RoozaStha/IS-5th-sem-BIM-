import random
from math import gcd

# Function to find the modular inverse
def mod_inverse(e, phi):
    for d in range(1, phi):
        if (e * d) % phi == 1:
            return d
    return None

# Function to perform modular exponentiation
def power(base, exponent, mod):
    result = 1
    base = base % mod
    while exponent > 0:
        if (exponent % 2) == 1:
            result = (result * base) % mod
        exponent = exponent >> 1
        base = (base * base) % mod
    return result

# Function to check if a number is prime
def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(num**0.5) + 1):
        if num % i == 0:
            return False
    return True

# Step 1: Get two large prime numbers from the user
while True:
    p = int(input("Enter a prime number (p): "))
    if is_prime(p):
        break
    else:
        print("Invalid input. Please enter a prime number.")

while True:
    q = int(input("Enter another prime number (q, different from p): "))
    if is_prime(q) and q != p:
        break
    else:
        print("Invalid input. Please enter a prime number different from p.")

# Step 2: Calculate n (p * q) and phi (Euler's totient function)
n = p * q
phi = (p - 1) * (q - 1)

# Step 3: Automatically select an integer e (1 < e < phi) that is coprime with phi
while True:
    e = random.randint(2, phi - 1)
    if gcd(e, phi) == 1:
        break

# Step 4: Calculate d, the modular inverse of e modulo phi
d = mod_inverse(e, phi)

# Display the generated public and private keys
print("\n--- RSA Key Generation ---")
print("Public key (e, n):", (e, n))
print("Private key (d, n):", (d, n))
print("Prime numbers (p, q):", (p, q))

# Function to encrypt a message
def encrypt(message, e, n):
    cipher = [power(ord(char), e, n) for char in message]
    return ''.join(chr(c) for c in cipher)  # Return encrypted message as text

# Function to decrypt a message
def decrypt(cipher, d, n):
    plain = [chr(power(ord(char), d, n)) for char in cipher]
    return ''.join(plain)  # Return decrypted message as text

# Test the RSA algorithm
message = input("\nEnter the message to encrypt: ")

# Ensure the message is in uppercase and only contains alphabetic characters (no special characters)
message = message.upper()
cipher_text = encrypt(message, e, n)

print("Encrypted message:", cipher_text)

decrypted_message = decrypt(cipher_text, d, n)
print("Decrypted message:", decrypted_message)