# distutils: language=c
# distutils: libraries=crypto,secp256k1
from cpython.mem cimport PyMem_Malloc, PyMem_Free
from libc.stdint cimport uint8_t, int32_t
from libc.stdlib cimport malloc, free
from libc.string cimport memset, memcpy
import os
import binascii
from typing import List, Tuple

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

cdef ringcip_DBPoE_context create_ring_context(secp256k1_context* ctx, 
                                              list topic_list,
                                              int topic_size,
                                              uint8_t** out_gen_seed,
                                              uint8_t** out_topic_list) noexcept:
    cdef:
        uint8_t* gen_seed = NULL
        uint8_t* topic_list_c = NULL
        int total_length = topic_size * 32  # Fixed size for topics
        int i, offset = 0
        bytes topic_bytes
    
    try:
        # Initialize gen_seed
        gen_seed = <uint8_t*>malloc(32)
        if gen_seed == NULL:
            raise MemoryError("Gen seed allocation failed")
        memset(gen_seed, GEN_SEED_FIX, 32)
        
        # Allocate space for topics
        topic_list_c = <uint8_t*>malloc(total_length)
        if topic_list_c == NULL:
            raise MemoryError("Topic list allocation failed")
            
        # Copy topics 
        for i in range(min(len(topic_list), topic_size)):
            topic_bytes = topic_list[i]
            memcpy(<void*>(topic_list_c + (i * 32)), 
                  <const unsigned char*>topic_bytes, 
                  min(len(topic_bytes), 32))
            
        # Create ring CIP context
        rctx = secp256k1_ringcip_DBPoE_context_create(
            ctx, 10, N, M, gen_seed, topic_list_c, topic_size
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

# Constants matching Go code
GEN_SEED_FIX = 11
N = 2
M = 10

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

def create_challenge() -> bytes:
    """Create a 32-byte challenge using OpenSSL RAND_bytes"""
    cdef uint8_t[32] chal
    
    if RAND_bytes(&chal[0], 32) != 1:
        raise RuntimeError("Failed to generate random bytes")
    return bytes(chal[:32])

def create_passkey(filename: str) -> None:
    """Create a 32-byte cryptographic passkey and save it to file"""
    cdef uint8_t[32] msk
    
    if RAND_bytes(&msk[0], 32) != 1:
        raise RuntimeError("Failed to generate random bytes")
    
    with open(filename, "wb") as f:
        f.write(bytes(msk[:32]))

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
        secp256k1_context* ctx
        ringcip_DBPoE_context rctx
        uint8_t[32] msk
        uint8_t[32] gen_seed
        pk_t mpk
        int total_length = sum(len(topic) for topic in topic_list)
        uint8_t* topics_buffer = <uint8_t*>malloc(total_length)
        int offset = 0
    
    try:            
        # Copy MSK
        memcpy(msk, <const unsigned char*>msk_bytes, 32)
        
        # Create context
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
        if ctx == NULL:
            raise RuntimeError("Failed to create context")
        
        # Initialize gen_seed
        memset(gen_seed, GEN_SEED_FIX, 32)
            
        # Copy topics
        for topic in topic_list:
            memcpy(topics_buffer + offset, <const unsigned char*><char*>topic, len(topic))
            offset += len(topic)
            
        # Create context and generate MPK - using fixed parameters as in Go
        rctx = secp256k1_ringcip_DBPoE_context_create(
            ctx, 10, N, M, gen_seed, topics_buffer, topic_list_size
        )
        
        if secp256k1_boquila_gen_DBPoE_mpk(ctx, &rctx, &mpk, &msk[0]) == 0:
            raise RuntimeError("Failed to generate MPK")
        

        return (<bytes>(<char*>&mpk)[:sizeof(pk_t)])
        
    finally:
        if topics_buffer:
            free(topics_buffer)
        if ctx:
            secp256k1_context_destroy(ctx)

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
    topic_index: int) -> Tuple[str, bytes, bytes, bool]:
    """
    Generate a registration proof for a given service.
    
    Args:
        index: Position in the ring
        current_m: Current ring depth
        current_N: Current ring size
        servicename: Name of the service (32 bytes)
        challenge: Random challenge (32 bytes)
        msk_bytes: Master secret key (32 bytes)
        id_list: List of known IDs
        topic_list: List of service topics
        topic_list_size: Number of topics
        topic_index: Index of the current topic
        
    Returns:
        Tuple of (proof_hex, spk_bytes, nullifier_bytes, success)
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
        pk_t* mpks = NULL
        pk_t spk
        int proof_len = 0
        int name_len = 32
        ringcip_DBPoE_context rctx
    
    try:     
        # Create context
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
        if ctx == NULL:
            raise CryptoError(0, "Context creation failed")
            
        # Copy input bytes to C arrays
        memcpy(&msk[0], <const unsigned char*>msk_bytes, 32)
        memcpy(&W[0], <const unsigned char*>challenge, 32)
        memcpy(&name[0], <const unsigned char*>servicename, 32)
            
        # Create ring context
        rctx = create_ring_context(ctx, topic_list, topic_list_size, &gen_seed, &topic_list_c)
            
        # Derive SSK
        if secp256k1_boquila_derive_ssk(ctx, &ssk[0], &msk[0], &name[0], name_len) == 0:
            raise CryptoError(0, "SSK derivation failed")
            
        # Derive SPK
        if secp256k1_boquila_derive_DBPoE_spk(ctx, &rctx, &spk, &ssk[0]) == 0:
            raise CryptoError(0, "SPK derivation failed")
            
        # Generate random bytes for auth proof
        if RAND_bytes(&r[0], 32) != 1:
            raise CryptoError(0, "Random bytes generation failed")
            
        # Create and verify auth proof
        proofnewPtr = <uint8_t*>&proofnew[0]
        if secp256k1_boquila_DBPoE_auth_prove(
            ctx, &rctx, proofnewPtr, &msk[0], &r[0], &name[0],
            name_len, &spk, &W[0]
        ) == 0:
            raise CryptoError(0, "Auth prove failed")
            
        if secp256k1_boquila_DBPoE_auth_verify(
            ctx, &rctx, proofnewPtr, &spk, &W[0]
        ) == 0:
            raise CryptoError(0, "Auth verify failed")
            
        # Prepare MPKs array
        mpks = <pk_t*>malloc(current_N * sizeof(pk_t))
        if mpks == NULL:
            raise MemoryError("MPKs allocation failed")
            
        for i in range(current_N):
            id_bytes = id_list[i]
            memcpy(&mpks[i].buf[0], <const unsigned char*>id_bytes, 33)
        
        # Allocate memory for proof and nullifier
        proof_len = secp256k1_zero_mcom_DBPoE_get_size(&rctx, current_m)
        proof = <uint8_t*>malloc(proof_len)
        nullifier = <uint8_t*>malloc(32)
        if proof == NULL or nullifier == NULL:
            raise MemoryError("Proof or nullifier allocation failed")
        memset(proof, 0, proof_len)
        memset(nullifier, 0, 32)

        # Create membership proof
        if secp256k1_boquila_prove_DBPoE_memmpk(
            ctx, &rctx, proof, nullifier, mpks, &msk[0], &W[0],
            &name[0], name_len, &spk, index, topic_index, current_N, current_m
        ) == 0:
            raise CryptoError(0, "Membership proof creation failed")
        
        # Convert proof to hex string
        proof_hex = binascii.hexlify(bytes(<unsigned char*>proof)[:proof_len]).decode('utf-8')
        
        # For verification, use the original proof rather than converting back and forth
        # Verify the generated proof
        result = secp256k1_boquila_verify_DBPoE_memmpk(
            ctx, &rctx, proof, nullifier, mpks, &W[0],
            &name[0], name_len, &spk, topic_index, current_N, current_m
        )
        
        
        if result == 0:
            print("\nVerification failed in registration_proof!")
            return "", None, None, False

        # Get SPK and nullifier bytes for return
        spk_bytes = bytes(<unsigned char*>&spk.buf[0])[:33]
        nullifier_bytes = bytes(<unsigned char*>nullifier)[:32]

        return proof_hex, spk_bytes, nullifier_bytes, True
        
    finally:
        if gen_seed != NULL:
            free(gen_seed)
        if topic_list_c != NULL:
            free(topic_list_c)
        if proof != NULL:
            free(proof)
        if mpks != NULL:
            free(mpks)
        if nullifier != NULL:
            free(nullifier)
        if ctx != NULL:
            secp256k1_context_destroy(ctx)
        

def registration_verify(
    proof_hex: str,
    current_m: int,
    current_N: int,
    servicename: bytes,
    challenge: bytes,
    id_list: List[bytes],
    spk_bytes: bytes,
    topic_list: List[bytes],
    topic_size: int,
    topic_index: int,
    nullifier_bytes: bytes) -> bool:
    """
    Verify a registration proof.
    
    Args:
        proof_hex: Hex-encoded proof string
        current_m: Current ring depth
        current_N: Current ring size
        servicename: Name of the service (32 bytes)
        challenge: Random challenge (32 bytes)
        id_list: List of known IDs
        spk_bytes: Service public key (33 bytes)
        topic_list: List of service topics
        topic_size: Number of topics
        topic_index: Index of the current topic
        nullifier_bytes: Nullifier value (32 bytes)
        
    Returns:
        bool: True if verification succeeds
    """
    
    cdef:
        secp256k1_context* ctx = NULL
        uint8_t[32] W  # challenge
        uint8_t[32] name
        uint8_t* gen_seed = NULL
        uint8_t* topic_list_c = NULL
        uint8_t* proof = NULL
        pk_t* mpks = NULL
        pk_t spk
        int name_len = 32
        ringcip_DBPoE_context rctx
    
    try:
        # Create context
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
        if ctx == NULL:
            raise CryptoError(0, "Context creation failed")
            
        # Copy challenge and name
        memcpy(&W[0], <const unsigned char*>challenge, 32)
        memcpy(&name[0], <const unsigned char*>servicename, 32)
        
        # Create ring context with same params as generation
        rctx = create_ring_context(ctx, topic_list, topic_size, &gen_seed, &topic_list_c)
            
        # Copy spk_bytes to spk structure
        memcpy(&spk.buf[0], <const unsigned char*>spk_bytes, 33)
        
        # Prepare and copy MPKs array
        mpks = <pk_t*>malloc(current_N * sizeof(pk_t))
        if mpks == NULL:
            raise MemoryError("MPKs allocation failed")
        
        for i in range(current_N):
            id_bytes = id_list[i]
            memcpy(&mpks[i].buf[0], <const unsigned char*>id_bytes, 33)
        
        # Decode hex proof and allocate memory
        proof_len = secp256k1_zero_mcom_DBPoE_get_size(&rctx, current_m)
        proof = <uint8_t*>malloc(proof_len)
        if proof == NULL:
            raise MemoryError("Proof allocation failed")
        
        try:
            proof_bytes = binascii.unhexlify(proof_hex)
            memcpy(proof, <const unsigned char*>proof_bytes, len(proof_bytes))
        except binascii.Error as e:
            raise ValueError(f"Invalid hex proof: {e}")
            
        # Copy nullifier
        nullifier = <uint8_t*>malloc(32)
        if nullifier == NULL:
            raise MemoryError("Nullifier allocation failed")
        memcpy(nullifier, <const unsigned char*>nullifier_bytes, 32)
        
        result = secp256k1_boquila_verify_DBPoE_memmpk(
            ctx, &rctx, proof, nullifier, mpks, &W[0],
            &name[0], name_len, &spk, topic_index, current_N, current_m
        )
        
        return result == 1
        
    finally:
        if gen_seed != NULL:
            free(gen_seed)
        if topic_list_c != NULL:
            free(topic_list_c)
        if proof != NULL:
            free(proof)
        if mpks != NULL:
            free(mpks)
        if nullifier != NULL:
            free(nullifier)
        if ctx != NULL:
            secp256k1_context_destroy(ctx)


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