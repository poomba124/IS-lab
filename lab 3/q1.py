from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# 1. Generate a new RSA key pair (public and private keys)
# 2048 bits is a commonly recommended key size for security.
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

# 2. Define the message to be encrypted
plaintext = b"Asymmetric Encryption"

# 3. Encrypt the message using the public key
# We use the PKCS#1 OAEP padding scheme, which is the modern standard.
cipher_rsa_encrypt = PKCS1_OAEP.new(public_key)
ciphertext = cipher_rsa_encrypt.encrypt(plaintext)

# 4. Decrypt the ciphertext using the private key
cipher_rsa_decrypt = PKCS1_OAEP.new(private_key)
decrypted_text = cipher_rsa_decrypt.decrypt(ciphertext)

# 5. Print the results and verify
print("--- RSA Encryption/Decryption ---")
print(f"Public Key (n, e):  ({public_key.n:x}, {public_key.e})")
# Note: The full private key also includes d, p, q, etc., but we'll just show n.
print(f"Private Key (n):    ({private_key.n:x})")
print("-" * 30)
print(f"Original Message:   {plaintext.decode()}")
print(f"Ciphertext (Hex):   {ciphertext.hex().upper()}")
print(f"Decrypted Message:  {decrypted_text.decode()}")

if plaintext == decrypted_text:
    print("\n✅ Verification Successful: The decrypted message matches the original.")
else:
    print("\n❌ Verification Failed!")