import time
import os

# --- 1. Setup: Publicly Known Parameters ---
# These parameters are from RFC 3526 for a 2048-bit group.
# They are public and can be known by everyone, including attackers.
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

# --- 2. Key Generation ---
print("--- Diffie-Hellman Key Exchange ---")

# Alice generates her private and public keys
start_time_alice = time.perf_counter()
alice_private_key = int.from_bytes(os.urandom(32), 'big')
alice_public_key = pow(g, alice_private_key, p)
alice_key_gen_time = (time.perf_counter() - start_time_alice) * 1000  # in ms

# Bob generates his private and public keys
start_time_bob = time.perf_counter()
bob_private_key = int.from_bytes(os.urandom(32), 'big')
bob_public_key = pow(g, bob_private_key, p)
bob_key_gen_time = (time.perf_counter() - start_time_bob) * 1000  # in ms

print("\n--- Key Generation ---")
print(f"Alice's Key Gen Time: {alice_key_gen_time:.4f} ms")
print(f"Bob's Key Gen Time:   {bob_key_gen_time:.4f} ms")
print(f"\nAlice's Public Key:  {hex(alice_public_key)}")
print(f"Bob's Public Key:    {hex(bob_public_key)}")

# --- 3. Key Exchange and Shared Secret Calculation ---

# Alice computes the shared secret using Bob's public key
start_time_alice_exchange = time.perf_counter()
alice_shared_secret = pow(bob_public_key, alice_private_key, p)
alice_exchange_time = (time.perf_counter() - start_time_alice_exchange) * 1000 # in ms

# Bob computes the shared secret using Alice's public key
start_time_bob_exchange = time.perf_counter()
bob_shared_secret = pow(alice_public_key, bob_private_key, p)
bob_exchange_time = (time.perf_counter() - start_time_bob_exchange) * 1000 # in ms

print("\n--- Shared Secret Calculation ---")
print(f"Alice's Exchange Time: {alice_exchange_time:.4f} ms")
print(f"Bob's Exchange Time:   {bob_exchange_time:.4f} ms")
print(f"\nAlice's Computed Secret: {hex(alice_shared_secret)}")
print(f"Bob's Computed Secret:   {hex(bob_shared_secret)}")

# --- 4. Verification ---
print("\n--- Verification ---")
if alice_shared_secret == bob_shared_secret:
    print("✅ Success: Shared secrets match!")
else:
    print("❌ Failure: Shared secrets do NOT match.")