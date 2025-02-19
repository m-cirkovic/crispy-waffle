# distutils: language=c
# distutils: libraries=crypto,secp256k1
from cpython.mem cimport PyMem_Malloc, PyMem_Free
from libc.stdint cimport uint8_t, int32_t
from libc.stdlib cimport malloc, free, realloc
from libc.string cimport memset, memcpy
import os
import binascii
from typing import List, Tuple
import logging
logger = logging.getLogger('u2sso')

# Security Configuration
cdef struct SecurityConfig:
    size_t MAX_PROOF_SIZE
    size_t MAX_TOPIC_SIZE
    size_t MAX_ID_LIST_SIZE

cdef SecurityConfig SECURITY_CONFIG = SecurityConfig(
    MAX_PROOF_SIZE=1024 * 1024,  # 1MB
    MAX_TOPIC_SIZE=1000,
    MAX_ID_LIST_SIZE=1000
)

# Declare the secp256k1 types from the header
cdef extern from "secp256k1.h":
    struct secp256k1_context_struct:
        pass
    ctypedef secp256k1_context_struct secp256k1_context

    int SECP256K1_CONTEXT_SIGN
    int SECP256K1_CONTEXT_VERIFY
    
    secp256k1_context* secp256k1_context_create(int flags)
    void secp256k1_context_destroy(secp256k1_context* ctx)

cdef extern from "secp256k1_generator.h":
    struct secp256k1_generator_struct:
        unsigned char data[64]
    ctypedef secp256k1_generator_struct secp256k1_generator

cdef extern from "secp256k1_ringcip.h":
    # Struct definitions
    struct pk_struct:
        uint8_t[33] buf
    ctypedef pk_struct pk_t

    struct ringcip_context_struct:
        int L
        int n
        int m
        int N
        secp256k1_generator* multigen
        secp256k1_generator geng
        secp256k1_generator genh
        secp256k1_generator genmu
    ctypedef ringcip_context_struct ringcip_context

    struct ringcip_DBPoE_context_struct:
        int L
        int n
        int m
        int N
        secp256k1_generator* multigen
        secp256k1_generator* geng
        secp256k1_generator genh
        secp256k1_generator genmu
        uint8_t* topics
        int topic_size
    ctypedef ringcip_DBPoE_context_struct ringcip_DBPoE_context

    # Function declarations
    ringcip_DBPoE_context secp256k1_ringcip_DBPoE_context_create(
        const secp256k1_context* ctx,
        int L, int n, int m,
        uint8_t* gen_seed,
        uint8_t* topics,
        int topic_size
    )

    int secp256k1_boquila_gen_DBPoE_mpk(
        const secp256k1_context* ctx,
        const ringcip_DBPoE_context* rctx,
        pk_t* mpk,
        const uint8_t* msk
    )

    int secp256k1_boquila_derive_ssk(
        const secp256k1_context* ctx,
        uint8_t* ssk,
        const uint8_t* msk,
        const uint8_t* name,
        int name_len
    )

    int secp256k1_boquila_derive_DBPoE_spk(
        const secp256k1_context* ctx,
        const ringcip_DBPoE_context* rctx,
        pk_t* spk,
        const uint8_t* ssk
    )

    int secp256k1_boquila_DBPoE_auth_prove(
        const secp256k1_context* ctx,
        const ringcip_DBPoE_context* rctx,
        uint8_t* proof,
        const uint8_t* msk,
        const uint8_t* r,
        const uint8_t* name,
        int name_len,
        pk_t* spk,
        uint8_t* chal
    )

    int secp256k1_boquila_DBPoE_auth_verify(
        const secp256k1_context* ctx,
        const ringcip_DBPoE_context* rctx,
        uint8_t* proof,
        pk_t* spk,
        uint8_t* chal
    )

    int secp256k1_boquila_prove_DBPoE_memmpk(
        const secp256k1_context* ctx,
        const ringcip_DBPoE_context* rctx,
        uint8_t* proof,
        uint8_t* nullifier,
        pk_t* mpks,
        const uint8_t* msk,
        const uint8_t* W,
        const uint8_t* name,
        int name_len,
        pk_t* spk,
        int32_t j,
        int topic_index,
        int32_t N,
        int m
    )

    int secp256k1_boquila_verify_DBPoE_memmpk(
        const secp256k1_context* ctx,
        const ringcip_DBPoE_context* rctx,
        uint8_t* proof,
        uint8_t* nullifier,
        pk_t* mpks,
        const uint8_t* W,
        const uint8_t* name,
        int name_len,
        pk_t* spk,
        int topic_index,
        int32_t N,
        int m
    )

    int secp256k1_zero_mcom_DBPoE_get_size(
        const ringcip_DBPoE_context* rctx,
        int m
    )

cdef extern from "openssl/rand.h":
    int RAND_bytes(unsigned char* buf, int num)

# Constants
cdef int N = 2
cdef int M = 10
cdef int GEN_SEED_FIX = 11

# Validation Functions
cdef int validate_bytes(bytes data, size_t expected_size, str name) except -1:
    if data is None:
        raise ValueError(f"{name} cannot be None")
    if <size_t>len(data) != expected_size:
        raise ValueError(f"{name} must be {expected_size} bytes, got {len(data)}")
    return 0

cdef int validate_list(list data, size_t expected_size, str name) except -1:
    if data is None:
        raise ValueError(f"{name} cannot be None")
    if <size_t>len(data) != expected_size:
        raise ValueError(f"{name} must have {expected_size} elements, got {len(data)}")
    return 0

# Resource Management
cdef class ResourceManager:
    cdef:
        void** resources
        size_t resource_count
        size_t capacity
        secp256k1_context* ctx

    def __cinit__(self):
        self.capacity = 16  # Initial capacity
        self.resources = <void**>malloc(self.capacity * sizeof(void*))
        self.resource_count = 0
        self.ctx = NULL
        if self.resources == NULL:
            raise MemoryError("Failed to allocate resource array")

    cdef void add_resource(self, void* resource) except *:
        cdef:
            void** new_resources = NULL

        if resource == NULL:
            return

        if self.resource_count >= self.capacity:
            # Grow array if needed
            self.capacity *= 2
            new_resources = <void**>realloc(self.resources, self.capacity * sizeof(void*))
            if new_resources == NULL:
                free(self.resources)
                self.resources = NULL
                raise MemoryError("Failed to resize resource array")
            self.resources = new_resources

        self.resources[self.resource_count] = resource
        self.resource_count += 1

    cdef void set_context(self, secp256k1_context* ctx) except *:
        self.ctx = ctx

    def __dealloc__(self):
        cdef size_t i
        if self.resources != NULL:
            for i in range(self.resource_count):
                if self.resources[i] != NULL:
                    free(self.resources[i])
            free(self.resources)
        if self.ctx != NULL:
            secp256k1_context_destroy(self.ctx)

# Secure Memory Operations
cdef int secure_zero_memory(void* ptr, size_t size) nogil:
    cdef:
        size_t i
        unsigned char* p = <unsigned char*>ptr
    for i in range(size):
        p[i] = 0
    return 1

cdef int secure_zero_pk(pk_t* pk) nogil:
    return secure_zero_memory(&pk.buf[0], sizeof(pk.buf))

# Error Handling
cdef class CryptoError(Exception):
    cdef public int code
    cdef public str message
    
    def __init__(self, int code, str message):
        self.code = code
        self.message = message

cdef int check_crypto_operation(int result, str operation) except -1:
    if result == 0:
        raise CryptoError(result, f"{operation} failed")
    return result

cdef ringcip_DBPoE_context create_ring_context(
    secp256k1_context* ctx, 
    list topic_list,
    size_t topic_size,  # Changed from int to size_t
    uint8_t** out_gen_seed,
    uint8_t** out_topic_list) noexcept:
    
    cdef:
        uint8_t* gen_seed = NULL
        uint8_t* topic_list_c = NULL
        size_t i  # Changed from int to size_t
        bytes topic_bytes
    
    if topic_size > SECURITY_CONFIG.MAX_TOPIC_SIZE:
        raise ValueError(f"Topic size exceeds maximum allowed ({SECURITY_CONFIG.MAX_TOPIC_SIZE})")
        
    validate_list(topic_list, topic_size, "topic_list")
    
    try:
        # Initialize gen_seed
        gen_seed = <uint8_t*>malloc(32)
        if gen_seed == NULL:
            raise MemoryError("Gen seed allocation failed")
        memset(gen_seed, GEN_SEED_FIX, 32)
        
        # Allocate space for topics
        topic_list_c = <uint8_t*>malloc(32 * topic_size)
        if topic_list_c == NULL:
            raise MemoryError("Topic list allocation failed")
            
        # Copy topics
        for i in range(topic_size):
            topic_bytes = topic_list[i]
            if len(topic_bytes) != 32:
                raise ValueError(f"Topic {i} must be exactly 32 bytes")
            memcpy(topic_list_c + (i * 32), <const unsigned char*>topic_bytes, 32)
            
        # Create ring CIP context
        rctx = secp256k1_ringcip_DBPoE_context_create(
            ctx, 10, N, M, gen_seed, topic_list_c, <int>topic_size  
        )
        
        # Set output pointers
        out_gen_seed[0] = gen_seed
        out_topic_list[0] = topic_list_c
        
        return rctx
        
    except:
        if gen_seed != NULL:
            free(gen_seed)
        if topic_list_c != NULL:
            free(topic_list_c)
        raise

def create_challenge() -> bytes:
    """Create a 32-byte challenge using OpenSSL RAND_bytes"""
    cdef uint8_t[32] chal
    secure_zero_memory(&chal[0], 32)
    
    if RAND_bytes(&chal[0], 32) != 1:
        raise RuntimeError("Failed to generate random bytes")
    return bytes(chal[:32])

def create_passkey(filename: str) -> None:
    """Create a 32-byte cryptographic passkey and save it to file"""
    cdef uint8_t[32] msk
    secure_zero_memory(&msk[0], 32)
    
    try:
        if RAND_bytes(&msk[0], 32) != 1:
            raise RuntimeError("Failed to generate random bytes")
        
        with open(filename, "wb") as f:
            f.write(bytes(msk[:32]))
    finally:
        secure_zero_memory(&msk[0], 32)

def load_passkey(filename: str) -> Tuple[bytes, bool]:
    """Load a 32-byte cryptographic passkey from file"""
    try:
        with open(filename, "rb") as f:
            data = f.read()
            if len(data) == 32:
                return data, True
            print(f"Invalid passkey length: expected 32, got {len(data)}")
            return None, False
    except Exception as e:
        print(f"Error loading passkey: {e}")
        return None, False

def create_id(msk_bytes: bytes, topic_list: List[bytes], topic_list_size: int) -> bytes:
    """Create a 33-byte ID using master secret key and topic list"""
    cdef:
        secp256k1_context* ctx = NULL
        uint8_t[32] msk
        uint8_t[32] gen_seed
        pk_t mpk
        int total_length = sum(len(topic) for topic in topic_list)
        uint8_t* topics_buffer = NULL
        int offset = 0
        ResourceManager resources = ResourceManager()
        ringcip_DBPoE_context rctx
    
    try:
        validate_bytes(msk_bytes, 32, "msk_bytes")
        validate_list(topic_list, topic_list_size, "topic_list")
        
        # Allocate topics buffer
        topics_buffer = <uint8_t*>malloc(total_length)
        if topics_buffer == NULL:
            raise MemoryError("Failed to allocate topics buffer")
        resources.add_resource(<void*>topics_buffer)
        
        secure_zero_memory(&msk[0], 32)
        secure_zero_memory(&gen_seed[0], 32)
        secure_zero_pk(&mpk)
        
        # Copy MSK
        memcpy(&msk[0], <const unsigned char*>msk_bytes, 32)
        
        # Create context
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
        if ctx == NULL:
            raise RuntimeError("Failed to create context")
        resources.set_context(ctx)
        
        # Initialize gen_seed
        memset(&gen_seed[0], GEN_SEED_FIX, 32)
            
        # Copy topics
        for topic in topic_list:
            validate_bytes(topic, 32, "topic")
            memcpy(topics_buffer + offset, <const unsigned char*><char*>topic, 32)
            offset += 32
            
        # Create context and generate MPK
        rctx = secp256k1_ringcip_DBPoE_context_create(
            ctx, 10, N, M, &gen_seed[0], topics_buffer, topic_list_size
        )
        
        check_crypto_operation(
            secp256k1_boquila_gen_DBPoE_mpk(ctx, &rctx, &mpk, &msk[0]),
            "MPK generation"
        )
        
        return bytes((<char*>&mpk)[:sizeof(pk_t)])
        
    finally:
        secure_zero_memory(&msk[0], 32)

def registration_proof(
    index: int,
    current_m: int,
    current_N: int,
    servicename: bytes,
    challenge: bytes,
    msk_bytes: bytes,
    id_list: List[bytes],
    topic_list: List[bytes],
    topic_list_size: int,
    topic_index: int) -> Tuple[bytes, bytes, bytes, bool]:
    """
    Generate registration proof with detailed debugging.
    """
    cdef:
        secp256k1_context* ctx = NULL
        uint8_t[32] msk
        uint8_t[32] ssk
        uint8_t[32] W  # challenge
        uint8_t[32] name
        uint8_t[32] r  # random bytes for auth
        uint8_t[65] proofnew  # For auth proof 
        uint8_t* gen_seed = NULL
        uint8_t* topic_list_c = NULL
        uint8_t* proof = NULL
        uint8_t* nullifier = NULL
        const char* proof_data_ver = NULL
        pk_t* mpks = NULL
        pk_t spk
        int proof_len
        int name_len = 32
        ringcip_DBPoE_context rctx
        int i
        bytes proof_bytes, spk_bytes, nullifier_bytes
        int result
        ResourceManager resources = ResourceManager()
        
    try:
        # Input validation
        validate_bytes(servicename, 32, "servicename")
        validate_bytes(challenge, 32, "challenge")
        validate_bytes(msk_bytes, 32, "msk_bytes")
        validate_list(id_list, current_N, "id_list")
        
        if current_N > SECURITY_CONFIG.MAX_ID_LIST_SIZE:
            raise ValueError(f"ID list size exceeds maximum allowed ({SECURITY_CONFIG.MAX_ID_LIST_SIZE})")
        
        memset(&spk, 0, sizeof(pk_t))
        
        # Create context
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
        if ctx == NULL:
            raise CryptoError(0, "Context creation failed")
        resources.set_context(ctx)
        
        # Copy input data
        memcpy(&msk[0], <const unsigned char*>msk_bytes, 32)
        memcpy(&W[0], <const unsigned char*>challenge, 32)
        memcpy(&name[0], <const unsigned char*>servicename, 32)
        
        # Create ring context
        rctx = create_ring_context(ctx, topic_list, topic_list_size, &gen_seed, &topic_list_c)
        if gen_seed != NULL:
            resources.add_resource(gen_seed)
        if topic_list_c != NULL:
            resources.add_resource(topic_list_c)
        
        # Derive SSK
        if secp256k1_boquila_derive_ssk(ctx, &ssk[0], &msk[0], &name[0], name_len) == 0:
            raise CryptoError(0, "SSK derivation failed")
        
        # Derive SPK
        if secp256k1_boquila_derive_DBPoE_spk(ctx, &rctx, &spk, &ssk[0]) == 0:
            raise CryptoError(0, "SPK derivation failed")
            
        # Auth proof section
        if RAND_bytes(&r[0], 32) != 1:
            raise CryptoError(0, "Random bytes generation failed")
            
        if secp256k1_boquila_DBPoE_auth_prove(
            ctx, &rctx, &proofnew[0], &msk[0], &r[0], &name[0],
            name_len, &spk, &W[0]
        ) == 0:
            raise CryptoError(0, "Auth prove failed")
            
        if secp256k1_boquila_DBPoE_auth_verify(
            ctx, &rctx, &proofnew[0], &spk, &W[0]
        ) == 0:
            raise CryptoError(0, "Auth verify failed")
            
        # Prepare MPKs array
        mpks = <pk_t*>malloc(current_N * sizeof(pk_t))
        if mpks == NULL:
            raise MemoryError("MPKs allocation failed")
        resources.add_resource(mpks)
            
        for i in range(current_N):
            if len(id_list[i]) != 33:
                raise ValueError(f"ID at index {i} must be 33 bytes")
            memcpy(&mpks[i].buf[0], <const unsigned char*>id_list[i], 33)
            logger.debug(f"MPK {i}: {bytes(mpks[i].buf[:33]).hex()}")
        
        # Membership proof section
        proof_len = secp256k1_zero_mcom_DBPoE_get_size(&rctx, current_m)
        if proof_len <= 0:
            logger.debug("Invalid proof length calculated")
            return b"", None, None, False
            
        proof = <uint8_t*>malloc(proof_len)
        nullifier = <uint8_t*>malloc(32)
        if proof == NULL or nullifier == NULL:
            logger.debug("Memory allocation failed")
            return b"", None, None, False
            
        resources.add_resource(proof)
        resources.add_resource(nullifier)
        
        memset(proof, 0, proof_len)
        memset(nullifier, 0, 32)
            
        if secp256k1_boquila_prove_DBPoE_memmpk(
            ctx, &rctx, proof, nullifier, mpks, &msk[0], &W[0],
            &name[0], name_len, &spk, index, topic_index, current_N, current_m
        ) == 0:
            raise CryptoError(0, "Membership proof creation failed")
        
        # Get bytes with additional validation
        proof_bytes = bytes(proof[:proof_len])
        spk_bytes = bytes(spk.buf[:33])
        nullifier_bytes = bytes(nullifier[:32])
        
        # Validate lengths
        if len(spk_bytes) != 33:
            logger.debug(f"Invalid SPK length after copy: {len(spk_bytes)}")
            return b"", None, None, False
            
        if len(nullifier_bytes) != 32:
            logger.debug(f"Invalid nullifier length after copy: {len(nullifier_bytes)}")
            return b"", None, None, False
        
        proof_hex = proof_bytes.hex()
        proof_hex_converted = binascii.unhexlify(proof_hex)

        # Create new buffer of exact size
        proof_ptr = <uint8_t*> malloc(proof_len)
        if proof_ptr == NULL:
            raise MemoryError("Failed to allocate memory for proof")
            
        # Copy each byte individually
        for i in range(proof_len):
            proof_ptr[i] = <uint8_t>proof_hex_converted[i]

        result = secp256k1_boquila_verify_DBPoE_memmpk(
            ctx, &rctx, proof_ptr, nullifier, mpks, &W[0],
            &name[0], name_len, &spk, topic_index, current_N, current_m
        )
        
        if result == 0:
            logger.debug("Verification failed!")
            return b"", None, None, False
            
        logger.debug("Verification successful!")
        return proof_hex, spk_bytes, nullifier_bytes, True
        
    finally:
        secure_zero_memory(&msk[0], 32)
        secure_zero_memory(&ssk[0], 32)
        secure_zero_memory(&r[0], 32)

def registration_verify(
    proof_hex: str,
    current_m: int,
    current_N: int,
    servicename: bytes,
    challenge: bytes,
    id_list: List[bytes],
    spk_bytes: bytes,
    topic_list: List[bytes],
    topic_list_size: int,
    topic_index: int,
    nullifier_bytes: bytes
) -> bool:
    """
    Verify registration proof with detailed debugging.
    """
    cdef:
        secp256k1_context* ctx = NULL
        uint8_t[32] W  # Challenge
        uint8_t[32] name
        pk_t* mpks = NULL
        pk_t spk
        uint8_t* proof_ptr = NULL
        uint8_t* nullifier_ptr = NULL
        uint8_t* gen_seed = NULL
        uint8_t* topic_list_c = NULL
        int proof_len
        int name_len = 32
        ringcip_DBPoE_context rctx
        int i
        int result
        ResourceManager resources = ResourceManager()

    
    # Input validation
    validate_bytes(servicename, 32, "servicename")
    validate_bytes(challenge, 32, "challenge")
    validate_list(id_list, current_N, "id_list")

    if current_N > SECURITY_CONFIG.MAX_ID_LIST_SIZE:
        raise ValueError(f"ID list size exceeds maximum allowed ({SECURITY_CONFIG.MAX_ID_LIST_SIZE})")

    memset(&spk, 0, sizeof(pk_t))

    # Create context
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
    if ctx == NULL:
        raise CryptoError(0, "Context creation failed")
    resources.set_context(ctx)

    # Copy input data
    memcpy(&W[0], <const unsigned char*>challenge, 32)
    memcpy(&name[0], <const unsigned char*>servicename, 32)

    # Create ring context
    rctx = create_ring_context(ctx, topic_list, topic_list_size, &gen_seed, &topic_list_c)
    if gen_seed != NULL:
        resources.add_resource(gen_seed)
    if topic_list_c != NULL:
        resources.add_resource(topic_list_c)

    # Load SPK
    if len(spk_bytes) != 33:
        raise ValueError("SPK bytes length must be 33")
    memcpy(&spk.buf[0], <const unsigned char*>spk_bytes, 33)

    # Prepare MPKs array
    mpks = <pk_t*>malloc(current_N * sizeof(pk_t))
    if mpks == NULL:
        raise MemoryError("MPKs allocation failed")
    resources.add_resource(mpks)

    for i in range(current_N):
        if len(id_list[i]) != 33:
            raise ValueError(f"ID at index {i} must be 33 bytes")
        memcpy(&mpks[i].buf[0], <const unsigned char*>id_list[i], 33)

    # Get proof length
    proof_len = secp256k1_zero_mcom_DBPoE_get_size(&rctx, current_m)
    if proof_len <= 0:
        logger.debug("Invalid proof length calculated")
        return False

    # Decode proofHex from hex string to bytes
    proof_hex_converted = binascii.unhexlify(proof_hex)

    # Allocate proof memory
    proof_ptr = <uint8_t*> malloc(proof_len)
    if proof_ptr == NULL:
        raise MemoryError("Failed to allocate memory for proof")
    resources.add_resource(proof_ptr)

    # Copy proof_hex_converted into proof_ptr
    memcpy(proof_ptr, <const char*> proof_hex_converted, proof_len)

    # Allocate nullifier memory and copy data
    nullifier_ptr = <uint8_t*> malloc(32)
    if nullifier_ptr == NULL:
        raise MemoryError("Failed to allocate memory for nullifier")
    resources.add_resource(nullifier_ptr)
    memcpy(nullifier_ptr, <const unsigned char*>nullifier_bytes, 32)

    # Verify proof
    result = secp256k1_boquila_verify_DBPoE_memmpk(
        ctx, &rctx, proof_ptr, nullifier_ptr, mpks, &W[0],
        &name[0], name_len, &spk, topic_index, current_N, current_m
    )

    if result == 0:
        logger.debug("Verification failed!")
        return False

    logger.debug("Verification successful!")
    return True



def auth_proof(
    servicename: bytes,
    challenge: bytes,
    msk_bytes: bytes,
    topic_list: List[bytes],
    topic_size: int) -> Tuple[str, bool]:
    """
    Generate an authentication proof.
    
    Args:
        servicename: Name of the service (32 bytes)
        challenge: Random challenge (32 bytes)
        msk_bytes: Master secret key (32 bytes)
        topic_list: List of service topics
        topic_size: Number of topics
        
    Returns:
        Tuple of (proof_hex, success)
    """
    cdef:
        secp256k1_context* ctx = NULL
        uint8_t[32] msk, ssk, W, name, r
        uint8_t[65] proofnew
        uint8_t *gen_seed = NULL
        uint8_t *topic_list_c = NULL
        pk_t spk
        int name_len = 32
        ringcip_DBPoE_context rctx
    
    try:
        # Initialize context and copy input data
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
        if ctx == NULL:
            raise CryptoError(0, "Context creation failed")
            
        memcpy(&msk[0], <const unsigned char*>msk_bytes, 32)
        memcpy(&W[0], <const unsigned char*>challenge, 32)
        memcpy(&name[0], <const unsigned char*>servicename, 32)
            
        # Create ring context
        rctx = create_ring_context(ctx, topic_list, topic_size, &gen_seed, &topic_list_c)
            
        # Derive keys
        if secp256k1_boquila_derive_ssk(ctx, &ssk[0], &msk[0], &name[0], name_len) == 0:
            return "", False
            
        if secp256k1_boquila_derive_DBPoE_spk(ctx, &rctx, &spk, &ssk[0]) == 0:
            return "", False
            
        # Generate auth proof
        if RAND_bytes(&r[0], 32) != 1:
            return "", False
            
        proofnewPtr = <uint8_t*>&proofnew[0]
        if secp256k1_boquila_DBPoE_auth_prove(
            ctx, &rctx, proofnewPtr, &msk[0], &r[0], &name[0],
            name_len, &spk, &W[0]
        ) == 0:
            return "", False
            
        if secp256k1_boquila_DBPoE_auth_verify(
            ctx, &rctx, proofnewPtr, &spk, &W[0]
        ) == 0:
            return "", False

        # Convert proof to hex string
        proof_hex = binascii.hexlify(bytes(proofnew[:65])).decode('utf-8')
        return proof_hex, True
        
    finally:
        if gen_seed != NULL:
            free(gen_seed)
        if topic_list_c != NULL:
            free(topic_list_c)
        if ctx != NULL:
            secp256k1_context_destroy(ctx)

def auth_verify(
    proof_hex: str,
    servicename: bytes,
    challenge: bytes,
    spk_bytes: bytes,
    topic_list: List[bytes],
    topic_size: int) -> bool:
    """
    Verify an authentication proof.
    
    Args:
        proof_hex: Hex-encoded proof string
        servicename: Name of the service (32 bytes)
        challenge: Random challenge (32 bytes)
        spk_bytes: Service public key (33 bytes)
        topic_list: List of service topics
        topic_size: Number of topics
        
    Returns:
        bool: True if verification succeeds
    """
    cdef:
        secp256k1_context* ctx = NULL
        uint8_t[32] W, name
        uint8_t *gen_seed = NULL
        uint8_t *topic_list_c = NULL
        uint8_t[65] proof
        pk_t spk
        int name_len = 32
        ringcip_DBPoE_context rctx
    
    try:
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
        if ctx == NULL:
            raise CryptoError(0, "Context creation failed")
            
        # Copy input data
        memcpy(&W[0], <const unsigned char*>challenge, 32)
        memcpy(&name[0], <const unsigned char*>servicename, 32)
        
        # Create context and copy SPK
        rctx = create_ring_context(ctx, topic_list, topic_size, &gen_seed, &topic_list_c)
        memcpy(&spk.buf[0], <const unsigned char*>spk_bytes, 33)
        
        # Convert and copy proof
        try:
            proof_bytes = binascii.unhexlify(proof_hex)
            memcpy(&proof[0], <const unsigned char*>proof_bytes, min(len(proof_bytes), 65))
        except binascii.Error as e:
            raise ValueError(f"Invalid hex proof: {e}")
        
        # Verify auth proof
        result = secp256k1_boquila_DBPoE_auth_verify(
            ctx, &rctx, &proof[0], &spk, &W[0]
        )
        
        return result == 1
        
    finally:
        if gen_seed != NULL:
            free(gen_seed)
        if topic_list_c != NULL:
            free(topic_list_c)
        if ctx != NULL:
            secp256k1_context_destroy(ctx)