import os
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from eth_keys.keys import PrivateKey
import ecies

# --- Helper Functions ---

def create_dummy_file(filename, size_mb):
    """Creates a file of a specific size with random data."""
    with open(filename, 'wb') as f:
        f.write(os.urandom(size_mb * 1024 * 1024))
    print(f"Created dummy file: {filename} ({size_mb} MB)")

# --- RSA Specific Functions ---

def generate_rsa_keys():
    """Generates a 2048-bit RSA key pair."""
    key = RSA.generate(2048)
    return key, key.publickey()

def rsa_hybrid_encrypt(public_key, data):
    """Encrypts data using an RSA-based hybrid scheme."""
    session_key = get_random_bytes(32)
    cipher_aes = AES.new(session_key, AES.MODE_GCM)
    encrypted_data, tag = cipher_aes.encrypt_and_digest(data)
    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)
    
    return encrypted_session_key, cipher_aes.nonce, tag, encrypted_data

def rsa_hybrid_decrypt(private_key, encrypted_session_key, nonce, tag, encrypted_data):
    """Decrypts data from an RSA-based hybrid scheme."""
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(encrypted_session_key)
    
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(encrypted_data, tag)
    
    return decrypted_data

# --- ECC Specific Functions ---

def generate_ecc_keys():
    """Generates an ECC (secp256r1) key pair."""
    private_key = PrivateKey(os.urandom(32))
    return private_key, private_key.public_key

def ecc_hybrid_encrypt(public_key, data):
    """Encrypts data using an ECC-based hybrid scheme (ECIES)."""
    session_key = get_random_bytes(32)
    cipher_aes = AES.new(session_key, AES.MODE_GCM)
    encrypted_data, tag = cipher_aes.encrypt_and_digest(data)
    
    # ECIES encrypts the session key
    encrypted_session_key = ecies.encrypt(public_key.to_hex(), session_key)
    
    return encrypted_session_key, cipher_aes.nonce, tag, encrypted_data
    
def ecc_hybrid_decrypt(private_key, encrypted_session_key, nonce, tag, encrypted_data):
    """Decrypts data from an ECC-based hybrid scheme."""
    # ECIES decrypts the session key
    session_key = ecies.decrypt(private_key.to_hex(), encrypted_session_key)
    
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(encrypted_data, tag)
    
    return decrypted_data
    
# --- Main Execution ---

if __name__ == "__main__":
    file_sizes = [1, 10]  # in MB
    
    for size in file_sizes:
        filename = f"testfile_{size}mb.bin"
        create_dummy_file(filename, size)
        
        with open(filename, 'rb') as f:
            file_data = f.read()

        # --- RSA Benchmark ---
        start_time = time.perf_counter()
        rsa_priv, rsa_pub = generate_rsa_keys()
        rsa_key_gen_time = (time.perf_counter() - start_time) * 1000

        start_time = time.perf_counter()
        rsa_enc_key, rsa_nonce, rsa_tag, rsa_enc_data = rsa_hybrid_encrypt(rsa_pub, file_data)
        rsa_encryption_time = (time.perf_counter() - start_time) * 1000

        start_time = time.perf_counter()
        rsa_dec_data = rsa_hybrid_decrypt(rsa_priv, rsa_enc_key, rsa_nonce, rsa_tag, rsa_enc_data)
        rsa_decryption_time = (time.perf_counter() - start_time) * 1000
        
        assert file_data == rsa_dec_data

        # --- ECC Benchmark ---
        start_time = time.perf_counter()
        ecc_priv, ecc_pub = generate_ecc_keys()
        ecc_key_gen_time = (time.perf_counter() - start_time) * 1000

        start_time = time.perf_counter()
        ecc_enc_key, ecc_nonce, ecc_tag, ecc_enc_data = ecc_hybrid_encrypt(ecc_pub, file_data)
        ecc_encryption_time = (time.perf_counter() - start_time) * 1000

        start_time = time.perf_counter()
        ecc_dec_data = ecc_hybrid_decrypt(ecc_priv, ecc_enc_key, ecc_nonce, ecc_tag, ecc_enc_data)
        ecc_decryption_time = (time.perf_counter() - start_time) * 1000
        
        assert file_data == ecc_dec_data
        
        # --- Report Results ---
        print(f"\n\n--- RESULTS FOR {size} MB FILE ---")
        print("===============================================================")
        print(f"| Metric             | RSA (2048-bit)      | ECC (secp256r1)   |")
        print(f"|--------------------|---------------------|-------------------|")
        print(f"| Key Gen Time       | {rsa_key_gen_time:17.2f} ms | {ecc_key_gen_time:15.2f} ms |")
        print(f"| Encryption Time    | {rsa_encryption_time:17.2f} ms | {ecc_encryption_time:15.2f} ms |")
        print(f"| Decryption Time    | {rsa_decryption_time:17.2f} ms | {ecc_decryption_time:15.2f} ms |")
        print(f"| Public Key Size    | {rsa_pub.size_in_bytes():>14} bytes | {len(ecc_pub.to_bytes()):>12} bytes |")
        print(f"| Private Key Size   | {rsa_priv.size_in_bytes():>13} bytes | {len(ecc_priv.to_bytes()):>12} bytes |")
        print("===============================================================")

        os.remove(filename)
