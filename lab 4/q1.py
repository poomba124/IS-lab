import os
import time
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# --- Publicly known Diffie-Hellman parameters (RFC 3526, 2048-bit Group) ---
# In a real system, these would be agreed upon by all parties.
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

# --- Key Management System ---
class CertificateAuthority:
    """Simulates a CA to manage and sign public keys."""
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        self.registry = {}
        print("✅ Certificate Authority initialized.")

    def issue_certificate(self, subsystem_name, subsystem_public_key):
        """Signs a subsystem's public key to create a certificate."""
        message = subsystem_name.encode() + subsystem_public_key.export_key('PEM')
        h = SHA256.new(message)
        signature = pss.new(self.key).sign(h)
        self.registry[subsystem_name] = (subsystem_public_key, signature)
        print(f"📄 CA issued a certificate for '{subsystem_name}'.")
        return signature

    def verify_certificate(self, subsystem_name, subsystem_public_key, signature):
        """Verifies that a certificate is valid."""
        try:
            message = subsystem_name.encode() + subsystem_public_key.export_key('PEM')
            h = SHA256.new(message)
            pss.new(self.public_key).verify(h, signature)
            print(f"✅ CA confirms certificate for '{subsystem_name}' is valid.")
            return True
        except (ValueError, TypeError):
            print(f"❌ CA warns: Certificate for '{subsystem_name}' is INVALID.")
            return False

# --- Subsystem Class ---
class SubSystem:
    """Represents a subsystem like Finance, HR, etc."""
    def __init__(self, name, ca: CertificateAuthority):
        self.name = name
        self.ca = ca
        
        # 1. Generate long-term RSA key pair for signing
        start_time = time.perf_counter()
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey()
        self.key_gen_time = (time.perf_counter() - start_time) * 1000
        
        # 2. Get a certificate for its public key from the CA
        self.certificate_signature = self.ca.issue_certificate(self.name, self.public_key)
        print(f"  - RSA Key Gen Time for {self.name}: {self.key_gen_time:.2f} ms")

    def initiate_key_exchange(self, recipient_name):
        """Generates and signs a DH public key."""
        # Generate ephemeral DH key pair
        self.dh_private_key = int.from_bytes(os.urandom(32), 'big')
        self.dh_public_key = pow(g, self.dh_private_key, p)
        
        # Sign the DH public key with our long-term RSA private key
        h = SHA256.new(str(self.dh_public_key).encode())
        signature = pss.new(self.rsa_key).sign(h)
        print(f"\n🤝 {self.name} is initiating key exchange with {recipient_name}.")
        return self.dh_public_key, signature

    def respond_and_compute_secret(self, initiator_name, initiator_dh_public, initiator_signature):
        """Verifies initiator and computes the shared secret."""
        # 1. Verify the initiator's certificate
        initiator_pub_key, initiator_cert_sig = self.ca.registry[initiator_name]
        if not self.ca.verify_certificate(initiator_name, initiator_pub_key, initiator_cert_sig):
            raise Exception("Authentication failed: Invalid certificate.")

        # 2. Verify the signature on the DH public key
        try:
            h = SHA256.new(str(initiator_dh_public).encode())
            pss.new(initiator_pub_key).verify(h, initiator_signature)
            print(f"✅ {self.name} verified RSA signature from {initiator_name}.")
        except (ValueError, TypeError):
            raise Exception("Authentication failed: Invalid DH key signature.")
            
        # 3. Compute shared secret
        start_time = time.perf_counter()
        shared_secret_int = pow(initiator_dh_public, self.dh_private_key, p)
        
        # Derive a 256-bit AES key from the shared secret using SHA-256
        self.aes_key = sha256(str(shared_secret_int).encode()).digest()
        exchange_time = (time.perf_counter() - start_time) * 1000
        print(f"  - Key Exchange Time for {self.name}: {exchange_time:.4f} ms")
        return self.aes_key

    def encrypt_document(self, document: bytes):
        """Encrypts a document using the derived AES key."""
        cipher_aes = AES.new(self.aes_key, AES.MODE_GCM)
        encrypted_doc, tag = cipher_aes.encrypt_and_digest(document)
        return encrypted_doc, tag, cipher_aes.nonce

    def decrypt_document(self, encrypted_doc, tag, nonce):
        """Decrypts a document using the derived AES key."""
        cipher_aes = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_doc = cipher_aes.decrypt_and_verify(encrypted_doc, tag)
        return decrypted_doc

# --- Main Simulation ---
if __name__ == "__main__":
    # 1. Initialize the Key Management System
    ca = CertificateAuthority()
    print("-" * 50)

    # 2. Initialize and Register Subsystems (Scalable)
    finance_system = SubSystem("Finance System", ca)
    hr_system = SubSystem("HR System", ca)
    supply_chain_system = SubSystem("Supply Chain System", ca)
    print("-" * 50)

    # 3. Simulate Secure Communication: Finance -> HR
    # Step A: Finance initiates the authenticated DH exchange
    finance_dh_pub, finance_dh_sig = finance_system.initiate_key_exchange(hr_system.name)

    # Step B: HR receives the request, generates its own DH keys, and computes the secret
    # (In a real system, HR would send its signed DH public key back)
    hr_dh_pub, hr_dh_sig = hr_system.initiate_key_exchange(finance_system.name) # HR generates its part
    
    print("\n--- Computing Shared Secret ---")
    finance_aes_key = finance_system.respond_and_compute_secret(hr_system.name, hr_dh_pub, hr_dh_sig)
    hr_aes_key = hr_system.respond_and_compute_secret(finance_system.name, finance_dh_pub, finance_dh_sig)

    # Verification
    assert finance_aes_key == hr_aes_key
    print("\n✅ Shared AES key successfully established between Finance and HR.")
    print(f"   Shared Key (first 8 bytes): {finance_aes_key[:8].hex()}...")
    print("-" * 50)
    
    # 4. Simulate Secure File Transfer
    financial_report = b"This is the Q3 financial report. Profits are up by 20%."
    print(f"Finance System wants to send a document:\n  '{financial_report.decode()}'")

    # Finance encrypts the document with the shared key
    encrypted_report, tag, nonce = finance_system.encrypt_document(financial_report)
    print(f"\nEncrypted Report (first 16 bytes): {encrypted_report[:16].hex()}...")
    
    # HR decrypts the document with the same shared key
    decrypted_report = hr_system.decrypt_document(encrypted_report, tag, nonce)
    print(f"HR System decrypted the document:\n  '{decrypted_report.decode()}'")
    
    # Final Verification
    assert financial_report == decrypted_report
    print("\n✅ Secure file transfer successful!")
    print("-" * 50)
    
    # 5. Demonstrate Scalability
    print("\n--- Demonstrating Scalability ---")
    logistics_system = SubSystem("Logistics System", ca)
    # Logistics can now securely communicate with any other registered system
    # using the same protocol.
    print("✅ New 'Logistics System' added and ready to communicate.")