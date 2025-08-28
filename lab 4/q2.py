import random
import sympy
import datetime
import hashlib

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS FOR RABIN CRYPTOSYSTEM
# -----------------------------------------------------------------------------

def power(a, b, c):
    """Modular exponentiation (a^b) % c."""
    x, y = 1, a
    while b > 0:
        if b % 2 == 1:
            x = (x * y) % c
        y = (y * y) % c
        b = b // 2
    return x % c

def extended_gcd(a, b):
    """Extended Euclidean Algorithm to find gcd and coefficients."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def sqrt_p(a, p):
    """Computes square root of a modulo p (where p = 3 (mod 4))."""
    if p % 4 != 3:
        raise ValueError("This simplified sqrt_p only works for primes p = 3 (mod 4)")
    return power(a, (p + 1) // 4, p)

# -----------------------------------------------------------------------------
# KEY MANAGEMENT SERVICE (KMS)
# -----------------------------------------------------------------------------

class KeyManagementService:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self._private_key_storage = {}  # Simulates secure, encrypted storage
        self.key_registry = {}  # Public keys and metadata
        self.revocation_list = set()
        self.logs = []
        print("✅ Key Management Service (KMS) Initialized.")

    def _log_event(self, event):
        log_entry = f"{datetime.datetime.now().isoformat()} - {event}"
        print(f"  [LOG] {log_entry}")
        self.logs.append(log_entry)

    def generate_rabin_pair(self, facility_id):
        """Generates a Rabin key pair (public n, private p, q)."""
        # Find two large primes p and q such that p, q = 3 (mod 4)
        p = sympy.randprime(2**(self.key_size//2 - 1), 2**(self.key_size//2))
        while p % 4 != 3:
            p = sympy.randprime(2**(self.key_size//2 - 1), 2**(self.key_size//2))
            
        q = sympy.randprime(2**(self.key_size//2 - 1), 2**(self.key_size//2))
        while q % 4 != 3:
            q = sympy.randprime(2**(self.key_size//2 - 1), 2**(self.key_size//2))

        n = p * q  # Public key
        private_key = (p, q)
        
        # Securely store and register the key
        self._private_key_storage[facility_id] = private_key
        self.key_registry[facility_id] = {
            "public_key": n,
            "created_at": datetime.datetime.now(),
            "expires_at": datetime.datetime.now() + datetime.timedelta(days=365)
        }
        self._log_event(f"Key pair generated for '{facility_id}'.")
        return n, private_key

    def distribute_keys(self, facility_id):
        """Securely provides a facility with its key pair."""
        if facility_id in self.revocation_list:
            self._log_event(f"Key distribution denied for revoked facility '{facility_id}'.")
            return None, None
        
        if facility_id not in self.key_registry:
            self._log_event(f"No keys found for '{facility_id}'. Generating new pair.")
            self.generate_rabin_pair(facility_id)

        public_key = self.key_registry[facility_id]["public_key"]
        private_key = self._private_key_storage[facility_id]
        self._log_event(f"Keys distributed to '{facility_id}'.")
        return public_key, private_key

    def revoke_key(self, facility_id):
        """Revokes the key for a facility."""
        if facility_id in self.key_registry:
            self.revocation_list.add(facility_id)
            del self.key_registry[facility_id]
            del self._private_key_storage[facility_id]
            self._log_event(f"Keys for '{facility_id}' have been revoked.")
            return True
        self._log_event(f"Revocation failed: No keys found for '{facility_id}'.")
        return False

    def renew_all_keys(self):
        """Simulates annual renewal of all non-revoked keys."""
        self._log_event("Starting annual key renewal process for all facilities.")
        all_facilities = list(self.key_registry.keys())
        for facility_id in all_facilities:
            print(f"\nRenewing key for '{facility_id}'...")
            self.generate_rabin_pair(facility_id)
        self._log_event("Annual key renewal process completed.")

# -----------------------------------------------------------------------------
# HEALTHCARE FACILITY SIMULATION
# -----------------------------------------------------------------------------

class HealthcareFacility:
    def __init__(self, facility_id, kms: KeyManagementService):
        self.id = facility_id
        self.kms = kms
        self.public_key = None
        self.private_key = None
        print(f"🏥 Facility '{self.id}' registered.")

    def request_keys(self):
        """Requests its key pair from the KMS."""
        print(f"\n'{self.id}' requesting keys from KMS...")
        self.public_key, self.private_key = self.kms.distribute_keys(self.id)
        if self.public_key:
            print(f"'{self.id}' received its keys.")
        else:
            print(f"'{self.id}' key request denied.")

    def encrypt(self, patient_record: str):
        """Encrypts data using its public key."""
        if not self.public_key:
            print("Cannot encrypt: No public key.")
            return None
        n = self.public_key
        # Convert string to integer and add padding for disambiguation
        m = int.from_bytes(f"PAD:{patient_record}".encode(), 'big')
        return power(m, 2, n)

    def decrypt(self, ciphertext):
        """Decrypts data using its private key."""
        if not self.private_key:
            print("Cannot decrypt: No private key.")
            return None
        p, q = self.private_key
        n = p * q
        
        # Find square roots modulo p and q
        r = sqrt_p(ciphertext, p)
        s = sqrt_p(ciphertext, q)

        # Use Chinese Remainder Theorem to find the four possible roots
        _, yp, yq = extended_gcd(p, q)
        r1 = (yp * p * s + yq * q * r) % n
        r2 = n - r1
        r3 = (yp * p * s - yq * q * r) % n
        r4 = n - r3
        
        # Find the correct root by checking the padding
        for root in [r1, r2, r3, r4]:
            try:
                byte_length = (root.bit_length() + 7) // 8
                decoded = root.to_bytes(byte_length, 'big').decode()
                if decoded.startswith("PAD:"):
                    return decoded.replace("PAD:", "")
            except (UnicodeDecodeError, AttributeError):
                continue
        return "Decryption failed: No valid message found."


# --- MAIN SIMULATION ---
if __name__ == "__main__":
    # Initialize the centralized service
    kms = KeyManagementService(key_size=1024)

    # Onboard facilities
    hospital_a = HealthcareFacility("City General Hospital", kms)
    clinic_b = HealthcareFacility("Suburb Wellness Clinic", kms)

    # Facilities request their keys
    hospital_a.request_keys()
    clinic_b.request_keys()

    # Simulate encryption and decryption
    patient_record = "Patient: John Doe, DOB: 1985-05-21, Condition: Stable"
    print(f"\nEncrypting record: '{patient_record}'")
    
    encrypted_record = hospital_a.encrypt(patient_record)
    print(f"Encrypted Record (Ciphertext): {encrypted_record}")
    
    decrypted_record = hospital_a.decrypt(encrypted_record)
    print(f"Decrypted Record: '{decrypted_record}'")
    assert patient_record == decrypted_record
    print("✅ Verification successful.")

    # Simulate key revocation
    print("\n--- Key Revocation Scenario ---")
    print(f"'{clinic_b.id}' is being decommissioned.")
    kms.revoke_key(clinic_b.id)
    clinic_b.request_keys() # This request will be denied

    # Simulate key renewal
    print("\n--- Key Renewal Scenario ---")
    kms.renew_all_keys()