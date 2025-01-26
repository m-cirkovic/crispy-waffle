import os
import hashlib
import binascii
from typing import List, Tuple
import u2sso

def create_32byte_hash(text: str) -> bytes:
    """Create a 32-byte hash using SHA-256"""
    return hashlib.sha256(text.encode('utf-8')).digest()

def print_hex(name: str, data: bytes):
    """Helper to print hex data in a consistent format"""
    print(f"{name}: {binascii.hexlify(data).decode('utf-8')}")

class TestU2SSO:
    @classmethod
    def setup_class(cls):
        """Set up test data that will be used across multiple tests"""
        # Create test topics list - matches Go code's GetAllServices
        cls.topics = [
            create_32byte_hash("topic.1"),
            create_32byte_hash("topic.2"),
            create_32byte_hash("topic.3"),
            create_32byte_hash("topic.4"),
            create_32byte_hash("test.service")
        ]
        cls.topic_size = len(cls.topics)

        # Service name should be 32 bytes (as seen in Go code)
        service_name = create_32byte_hash("test.service")
        cls.service_name = service_name[:32]  # Ensure 32 bytes

        # Create test MSK
        filename = "test_passkey.bin"
        u2sso.create_passkey(filename)
        cls.msk, success = u2sso.load_passkey(filename)
        assert success, "Failed to load passkey"
        
        # Create test IDs matching Go format (33 bytes each)
        cls.id_list = [
            u2sso.create_id(cls.msk, cls.topics, cls.topic_size),
            u2sso.create_id(os.urandom(32), cls.topics, cls.topic_size),  # Different MSK
            u2sso.create_id(os.urandom(32), cls.topics, cls.topic_size)   # Different MSK
        ]
    
    def test_create_challenge(self):
        """Test challenge creation"""
        print("\nTesting create_challenge...")
        
        # Create challenge
        challenge = u2sso.create_challenge()
        
        # Verify challenge
        assert isinstance(challenge, bytes), "Challenge should be bytes"
        assert len(challenge) == 32, "Challenge should be 32 bytes"
        print_hex("Challenge", challenge)

    def test_create_and_load_passkey(self):
        """Test passkey creation and loading"""
        print("\nTesting passkey creation and loading...")
        filename = "test_passkey.bin"
        
        try:
            # Create passkey
            u2sso.create_passkey(filename)
            assert os.path.exists(filename), "Passkey file should exist"
            
            # Check file size
            size = os.path.getsize(filename)
            print(f"Passkey file size: {size} bytes")
            assert size == 32, "Passkey file should be 32 bytes"
            
            # Load passkey
            passkey, success = u2sso.load_passkey(filename)
            assert success, "Passkey loading should succeed"
            assert isinstance(passkey, bytes), "Passkey should be bytes"
            assert len(passkey) == 32, "Passkey should be 32 bytes"
            print_hex("Passkey", passkey)
            
        finally:
            if os.path.exists(filename):
                os.remove(filename)
                assert not os.path.exists(filename), "Passkey file should be deleted"

    def test_create_id(self):
        """Test ID creation"""
        print("\nTesting create_id...")

        # Create ID
        id_bytes = u2sso.create_id(self.msk, self.topics, len(self.topics))
        
        # Verify ID
        assert isinstance(id_bytes, bytes), "ID should be bytes"
        assert len(id_bytes) == 33, "ID should be 33 bytes"
        print_hex("ID", id_bytes)
        
        # Create another ID and verify it's different
        id_bytes2 = u2sso.create_id(self.msk, self.topics, len(self.topics))
        assert id_bytes == id_bytes2, "Same input should produce same ID"

    def test_registration_verify(self):
        """Test complete registration proof and verification flow"""
        print("\nTesting registration verification flow...")
        
        # Create challenge once and reuse it
        challenge = u2sso.create_challenge()
        
        # Create proof first
        proof_hex, spk_bytes, nullifier_bytes, success = self.test_registration_proof_internal(challenge)
        assert success, "Failed to create registration proof"
        
        # Calculate current_m exactly like Go
        ring_size = len(self.id_list)
        id_size = len(self.id_list)
        current_m = 1
        tmp = 1
        while current_m < u2sso.M:  # Using constant M from u2sso
            tmp *= u2sso.N  # Using constant N from u2sso
            if tmp >= ring_size:
                break
            current_m += 1
        
        print("\nVERIFICATION PARAMETERS:")
        print(f"id_size: {id_size}")
        print(f"current_m: {current_m}")
        print(f"topic_index: {4}")
        print(f"id_list length: {len(self.id_list)}")
        print("id_list:")
        for i, id_bytes in enumerate(self.id_list):
            print(f"  {i}: {binascii.hexlify(id_bytes)}")
        
        verified = u2sso.registration_verify(
            proof_hex=proof_hex,
            current_m=current_m,
            current_N=id_size,
            servicename=self.service_name,
            challenge=challenge,  # Use the same challenge!
            id_list=self.id_list,
            spk_bytes=spk_bytes,
            topic_list=self.topics,
            topic_size=self.topic_size,
            topic_index=4,
            nullifier_bytes=nullifier_bytes
        )
        
        assert verified, "Registration verification failed"

    def test_registration_proof_internal(self, challenge):
        """Internal helper for proof creation using a specific challenge"""
        # Calculate current_m and ring_size as in Go code
        current_m = 1
        ring_size = 1
        id_size = len(self.id_list)
        
        for i in range(1, u2sso.M):
            ring_size = u2sso.N * ring_size
            if ring_size >= id_size:
                current_m = i
                break
                
        print(f"Ring size: {id_size}, m: {current_m}")

        topic_index = 4
        index = 0
        
        return u2sso.registration_proof(
            index=index,
            current_m=current_m,
            current_N=id_size,
            servicename=self.service_name,
            challenge=challenge,
            msk_bytes=self.msk,
            id_list=self.id_list,
            topic_list=self.topics,
            topic_list_size=self.topic_size,
            topic_index=topic_index
        )

    def test_registration_proof(self):
        """Test registration proof creation"""
        print("\nTesting registration_proof...")
        challenge = u2sso.create_challenge()
        return (*self.test_registration_proof_internal(challenge), challenge)

    def test_auth_flow(self):
        """Test complete authentication proof and verification flow"""
        print("\nTesting authentication flow...")
        
        # Create challenge
        challenge = u2sso.create_challenge()
        print_hex("Auth Challenge", challenge)
        
        # Create auth proof
        proof_hex, success = u2sso.auth_proof(
            servicename=self.service_name,
            challenge=challenge,
            msk_bytes=self.msk,
            topic_list=self.topics,
            topic_size=self.topic_size
        )
        
        assert success, "Failed to create auth proof"
        print_hex("Auth Proof", binascii.unhexlify(proof_hex))
        
        # Get SPK for verification
        # We need to derive the SPK similarly to how it's done in auth_proof
        ctx = None
        try:
            # Create a quick SPK using registration_proof 
            _, spk_bytes, _, success = self.test_registration_proof_internal(challenge)
            assert success, "Failed to get SPK"
            
            # Verify auth proof
            verified = u2sso.auth_verify(
                proof_hex=proof_hex,
                servicename=self.service_name,
                challenge=challenge,
                spk_bytes=spk_bytes,
                topic_list=self.topics,
                topic_size=self.topic_size
            )
            
            assert verified, "Auth verification failed"
            print("Auth verification successful")
            
        finally:
            if ctx:
                pass

if __name__ == "__main__":
    test = TestU2SSO()
    test.setup_class()
    
    print("=== Starting U2SSO Tests ===")
    print("\nTest 1: Creation and Loading")
    test.test_create_challenge()
    test.test_create_and_load_passkey()
    test.test_create_id()
    
    print("\nTest 2: Registration")
    test.test_registration_verify()
    
    print("\nTest 3: Authentication")
    test.test_auth_flow()
    
    print("\n=== All Tests Completed Successfully ===")