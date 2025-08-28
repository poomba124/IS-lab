import random

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------

def string_to_int(text: str) -> int:
    """Converts a string to a large integer."""
    return int.from_bytes(text.encode('utf-8'), 'big')

def int_to_string(num: int) -> str:
    """Converts a large integer back to a string."""
    byte_length = (num.bit_length() + 7) // 8
    return num.to_bytes(byte_length, 'big').decode('utf-8')

# -----------------------------------------------------------------------------
# ELGAMAL CORE FUNCTIONS
# -----------------------------------------------------------------------------

def generate_keys(p, g):
    """
    Generates an ElGamal public/private key pair.
    
    Returns:
        tuple: (public_key, private_key)
        public_key is a tuple (p, g, h)
        private_key is an integer x
    """
    x = random.randint(2, p - 2)  # Private key
    h = pow(g, x, p)              # Public key component
    return ((p, g, h), x)

def encrypt(public_key, plaintext):
    """
    Encrypts a plaintext string using an ElGamal public key.
    
    Returns:
        tuple: Ciphertext (c1, c2)
    """
    p, g, h = public_key
    m = string_to_int(plaintext)

    k = random.randint(2, p - 2)      # Ephemeral (one-time) key
    c1 = pow(g, k, p)
    s = pow(h, k, p)                  # Shared secret
    c2 = (m * s) % p
    
    return (c1, c2)

def decrypt(public_key, private_key, ciphertext):
    """
    Decrypts an ElGamal ciphertext using the private key.
    
    Returns:
        str: The original plaintext message.
    """
    p, _, _ = public_key
    x = private_key
    c1, c2 = ciphertext

    s = pow(c1, x, p)                 # Recreate shared secret
    # Compute modular inverse of s to "unmask" the message
    # In Python 3.8+, pow(s, -1, p) is the standard way to do this.
    # Your method, pow(s, p - 2, p), is also correct based on Fermat's Little Theorem.
    s_inv = pow(s, -1, p)

    decrypted_int = (c2 * s_inv) % p
    return int_to_string(decrypted_int)

# -----------------------------------------------------------------------------
# MAIN DRIVER
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # 1. Setup Parameters
    # p is a 2048-bit safe prime (Oakley Group 14 from RFC 3526)
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2
    plaintext = "Confidential Data"

    print("--- ElGamal Encryption Scheme ---")
    print(f"Using {p.bit_length()}-bit prime.\n")

    # 2. Key Generation
    public_key, private_key = generate_keys(p, g)
    print("--- Keys ---")
    print(f"Public Key (h):  {hex(public_key[2])}")
    print(f"Private Key (x): {hex(private_key)}\n")

    # 3. Encryption
    ciphertext = encrypt(public_key, plaintext)
    print("--- Encryption ---")
    print(f"Original Message: {plaintext}")
    print(f"Ciphertext (c1):  {hex(ciphertext[0])}")
    print(f"Ciphertext (c2):  {hex(ciphertext[1])}\n")

    # 4. Decryption
    decrypted_message = decrypt(public_key, private_key, ciphertext)
    print("--- Decryption ---")
    print(f"Decrypted Message: {decrypted_message}\n")

    # 5. Verification
    print("--- Verification ---")
    assert plaintext == decrypted_message
    print("✅ Success: Original and decrypted messages match.")