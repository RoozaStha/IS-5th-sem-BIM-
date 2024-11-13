import struct

# MD5 Constants
s = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21]
initial_values = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

# MD5 functions
def F(x, y, z):
    return (x & y) | (~x & z)

def G(x, y, z):
    return (x & z) | (y & ~z)

def H(x, y, z):
    return x ^ y ^ z

def I(x, y, z):
    return y ^ (x | ~z)

# Rotate left function
def rotate_left(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

# Padding function
def padding(message):
    # Length in bits
    length = len(message) * 8
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += struct.pack('<Q', length)  # Append the length as 64-bit
    return message

# Main MD5 transform function
def md5_transform(state, block):
    # Break the block into 16 32-bit words
    x = list(struct.unpack('<16I', block))
    
    a, b, c, d = state
    
    for i in range(64):
        if 0 <= i < 16:
            f = F(b, c, d)
            g = i
        elif 16 <= i < 32:
            f = G(b, c, d)
            g = (5 * i + 1) % 16
        elif 32 <= i < 48:
            f = H(b, c, d)
            g = (3 * i + 5) % 16
        else:
            f = I(b, c, d)
            g = (7 * i) % 16
        
        temp = d
        d = c
        c = b
        b = b + rotate_left(a + f + x[g], s[i % 16])  # Corrected with modulo for index wrap
        a = temp
    
    # Update the state
    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state = [x & 0xFFFFFFFF for x in state]  # Ensure 32-bit truncation

    return state

# MD5 hash function
def md5(message):
    # Initialize the MD5 state
    state = initial_values.copy()
    
    # Preprocess the message with padding
    message = padding(message)
    
    # Process each 512-bit block
    for i in range(0, len(message), 64):
        block = message[i:i + 64]
        state = md5_transform(state, block)

    # Return the final hash as a 128-bit number in hexadecimal
    return ''.join(f'{x:08x}' for x in state)

# Main execution
if __name__ == "__main__":
    # Get the input from the user
    input_str = input("Enter the string to hash: ").encode()
    
    # Calculate the MD5 hash
    hash_result = md5(input_str)
    
    # Output the result
    print("MD5 Hash:", hash_result)
