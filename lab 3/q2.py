import ecies
import binascii

# 1. Generate a new ECC key pair
# The private key is 32 bytes of random data.
# The public key is derived from the private key.
private_key = ecies.utils.generate_eth_key()
private_key_hex = private_key.to_hex()
public_key_hex = private_key.public_key.to_hex()

# 2. Define the message to be encrypted
plaintext = b"Secure Transactions"

# 3. Encrypt the message using the public key
# The library handles the complex ECIES steps automatically:
# - Creates a temporary (ephemeral) key pair.
# - Derives a shared secret using ECDH.
# - Uses the secret to encrypt the data with AES.
ciphertext = ecies.encrypt(public_key_hex, plaintext)

# 4. Decrypt the ciphertext using the private key
# The library re-derives the same shared secret to decrypt the data.
decrypted_text = ecies.decrypt(private_key_hex, ciphertext)

# 5. Print the results and verify
print("--- ECC Hybrid Encryption (ECIES) ---")
print(f"Private Key (Hex):  {private_key_hex}")
print(f"Public Key (Hex):   {public_key_hex}")
print("-" * 35)
print(f"Original Message:   {plaintext.decode()}")
# Use binascii to get a readable hex representation of the ciphertext
print(f"Ciphertext (Hex):   {binascii.hexlify(ciphertext).decode().upper()}")
print(f"Decrypted Message:  {decrypted_text.decode()}")

if plaintext == decrypted_text:
    print("\n✅ Verification Successful: The decrypted message matches the original.")
else:
    print("\n❌ Verification Failed!")