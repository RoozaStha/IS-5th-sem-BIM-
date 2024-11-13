# Import necessary libraries for bit manipulation
from Crypto.Util import number
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

# Initial Permutation Table
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final Permutation Table
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Expansion Table (E)
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# Permutation (P) after S-box substitution
P = [16, 7, 20, 21,
     29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2, 8, 24, 14,
     32, 27, 3, 9,
     19, 13, 30, 6,
     22, 11, 4, 25]

# Permuted Choice 1 (PC-1) for key schedule
PC_1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

# Permuted Choice 2 (PC-2) for key schedule
PC_2 = [14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32]

# Number of left shifts for each round in key schedule
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2,
                 1, 2, 2, 2, 2, 2, 2, 1]

# Define all 8 S-boxes
S_BOXES = [
    # S-box 1
    [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    ],
    # S-box 2
    [
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
        [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
        [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
        [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    ],
    # S-box 3
    [
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
        [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
        [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
        [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    ],
    # S-box 4
    [
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
        [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
        [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
        [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    ],
    # S-box 5
    [
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
        [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
        [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
        [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    ],
    # S-box 6
    [
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
        [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
        [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    ],
    # S-box 7
    [
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
        [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
        [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
        [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    ],
    # S-box 8
    [
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
        [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
        [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
        [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
    ],
]

# Helper function to convert binary string to list of bits
def str_to_bit_list(data, length=64):
    # Pads the binary string to the required length and converts it to a list of bits
    if len(data) < length:
        data = data.zfill(length)  # Pads with zeros on the left
    elif len(data) > length:
        data = data[-length:]  # Truncates to the rightmost 'length' bits
    return [int(bit) for bit in data]

# Permutation function
def permute(block, table):
    return [block[i - 1] for i in table]

# Left shift function for key schedule
def left_shift(bits, n):
    return bits[n:] + bits[:n]

# Generate 16 subkeys, each 48 bits
def generate_subkeys(key):
    # Apply PC-1 to get 56-bit key
    key_permuted = permute(key, PC_1)
    C = key_permuted[:28]
    D = key_permuted[28:]
    subkeys = []
    for shift in SHIFT_SCHEDULE:
        C = left_shift(C, shift)
        D = left_shift(D, shift)
        combined = C + D
        subkey = permute(combined, PC_2)  # 48 bits
        subkeys.append(subkey)
    return subkeys

# Substitution using all 8 S-boxes
def substitution(expanded_R):
    output = []
    # Divide expanded_R into 8 blocks of 6 bits
    for i in range(8):
        block = expanded_R[i*6:(i+1)*6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        s_box_value = S_BOXES[i][row][col]
        # Convert to 4-bit binary
        bits = [int(x) for x in bin(s_box_value)[2:].zfill(4)]
        output.extend(bits)
    return output  # 32 bits

# DES encryption process
def des_encrypt(plaintext, key):
    # Generate 16 subkeys
    subkeys = generate_subkeys(key)

    # Initial Permutation
    permuted_text = permute(plaintext, IP)

    # Split into left and right halves
    L, R = permuted_text[:32], permuted_text[32:]

    # 16 Rounds of Feistel structure
    for i in range(16):
        # Expand the right half from 32 to 48 bits
        expanded_R = permute(R, E)
        
        # XOR with the round subkey
        xor_result = [x ^ y for x, y in zip(expanded_R, subkeys[i])]
        
        # Substitution using S-boxes to get 32 bits
        substituted = substitution(xor_result)
        
        # Permutation P
        permuted_substituted = permute(substituted, P)
        
        # XOR with the left half
        new_R = [l ^ p for l, p in zip(L, permuted_substituted)]
        
        # Prepare for the next round
        L, R = R, new_R  # Swap halves

    # Combine R and L (note the swap after the last round)
    combined = R + L

    # Final Permutation
    cipher_text = permute(combined, FP)
    return cipher_text

# Function to convert bit list to binary string
def bit_list_to_str(bits):
    return ''.join(str(bit) for bit in bits)

# Example Usage
if __name__ == "__main__":
    # Example plaintext and key (binary strings)
    plaintext = "1101011100111010"  # 16 bits
    key = "1010001010"  # 10 bits

    # Convert plaintext and key to 64-bit lists
    plaintext_bits = str_to_bit_list(plaintext, 64)
    key_bits = str_to_bit_list(key, 64)

    # Run DES encryption
    cipher = des_encrypt(plaintext_bits, key_bits)
    cipher_text_str = bit_list_to_str(cipher)
    print("Cipher Text:", cipher_text_str)

   

# Key must be 8 bytes (64 bits)
key = b'8bytekey'

# Create DES cipher in ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# Plaintext must be a multiple of 8 bytes
plaintext = b'12345678'

# Encrypt
ciphertext = cipher.encrypt(plaintext)
print("Cipher Text:", ciphertext)

# Decrypt
decrypted = cipher.decrypt(ciphertext)
print("Decrypted Text:", decrypted)

