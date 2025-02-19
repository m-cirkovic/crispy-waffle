#!/usr/bin/env python
import logging
import binascii
import sys

# Import the U2SSO module
import u2sso

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    stream=sys.stdout)
logger = logging.getLogger(__name__)

def test_proof_length_consistency(runs=20):
    """Test if the proof length is consistent across multiple runs"""
    logger.info(f"Testing proof length consistency across {runs} runs")
    
    # Parameters from the provided example
    id_index = 3
    current_m = 2
    id_size = 4
    service_name = b'\x99\x1c\xab\xe7\x80:\xb7\xf1\x8a\xcbA\x95KeOu\xda\x1c\x84\x13\x9d\x87\xa2\rT.\xc8\xcd/\x86$7'
    challenge = b'\x85\xae\xd6\xfd\xc7UTHGe\x93\xdd\x1fs\x02i\x18\xbfAw#\xd9\x88\xc1L\xb2\xb2\rjuBQ'
    msk = b'UJ\x96\xcc\xe2\x91\x01\xb4\xb8\xfeOAT\xea\xe7\xf9\xa8\xc16\xa8\xadPZ2\xe2\xd2\x86)9\xdc9\xf3'
    
    id_list = [
        b'\x08\xcc\xb0"\x9b\x89\x0f\x8a\x90\xce!\xa7=\x97\xa4\x80Y\xdf\xc1\xeb\x80\xc5+\xa3*\x18\xaa\x9d\xdb\x06\x17})',
        b'\t\xae\xa3\xd5\x9b\xe1\xe8\xcb\x11\xc4\xa2r\x00\xa4Y\xd3\x1c\xea\x9dZ0\xf3\xd9\xc9[B\x18\xcd\x1dw7L\x17',
        b'\t8\xd6\xe8\x8f \xcb\x92\xf6\x0e\xb2\xb3\x19\x08zV\x0e\x1a\x1e\xc9\xd3\xa7$\xd0:8\xb9\x02\xaf\xdek8\x8e',
        b'\x08^kZ\xe7\xd7g\xbf\xb7l\xa8\xbe\x17\xe6\n\\\xfe\xb7\xd1\xa68?\xd8*\x06\x05\x0b\x08\x1a\xef\xf2\x8c\r'
    ]
    
    topic_list = [
        b'\xc8\xd9\xdf\xa6\xf2C\x9b\xcb\x0f\xdf\x00\xef\xafJEw\xd1A\xa8Y\x02\xb0\xb7[\x01\xd2\x99/\xadY\x12\xc3',
        b'cc\xecc\x88\xafGLCR\xd0J%\xfde\x0c\xa8\xe9\x13\xeb\x89\xbb\x89\x04D\xf5\x03\xf0\xc7\xf8QQ',
        b'\x0c+.\xddX\x8f\xe2\xf2\xd0\x8e\xed\xc0Ct3\xd8\x86\x15\xe0!,=\xee1\t\xf6z\xae\x98\xc6l\x04',
        b'\x99\x1c\xab\xe7\x80:\xb7\xf1\x8a\xcbA\x95KeOu\xda\x1c\x84\x13\x9d\x87\xa2\rT.\xc8\xcd/\x86$7'
    ]
    
    topic_list_size = 4
    topic_index = 3
    
    # Store results
    proof_lengths = []
    hex_lengths = []
    spk_lengths = []
    nullifier_lengths = []
    
    # Run the test multiple times
    for i in range(runs):
        logger.info(f"Run {i+1}/{runs}")
        
        proof_hex, spk_bytes, nullifier_bytes, success = u2sso.registration_proof(
            id_index,
            current_m,
            id_size,
            service_name,
            challenge,
            msk,
            id_list,
            topic_list,
            topic_list_size,
            topic_index
        )
        
        if not success:
            logger.error(f"Run {i+1}: Proof generation failed")
            continue
            
        # Track lengths
        proof_bytes = binascii.unhexlify(proof_hex)
        proof_lengths.append(len(proof_bytes))
        hex_lengths.append(len(proof_hex))
        spk_lengths.append(len(spk_bytes))
        nullifier_lengths.append(len(nullifier_bytes))
        
        logger.info(f"Run {i+1}: Proof binary length={len(proof_bytes)} bytes, hex length={len(proof_hex)} chars")
        
        # Verify the proof still works
        verified = u2sso.registration_verify(
            proof_hex,
            current_m,
            id_size,
            service_name,
            challenge,
            id_list,
            spk_bytes,
            topic_list,
            topic_list_size,
            topic_index,
            nullifier_bytes
        )
        
        if not verified:
            logger.error(f"Run {i+1}: Verification failed!")
    
    # Check if all lengths are the same
    consistent_proof_length = len(set(proof_lengths)) == 1
    consistent_hex_length = len(set(hex_lengths)) == 1
    consistent_spk_length = len(set(spk_lengths)) == 1
    consistent_nullifier_length = len(set(nullifier_lengths)) == 1
    
    # Display statistics
    logger.info("\n=== RESULTS ===")
    logger.info(f"Consistent proof binary length: {consistent_proof_length}")
    if consistent_proof_length:
        logger.info(f"  Proof binary length: {proof_lengths[0]} bytes")
    else:
        logger.info(f"  Proof binary lengths observed: {sorted(set(proof_lengths))} bytes")
        
    logger.info(f"Consistent proof hex length: {consistent_hex_length}")
    if consistent_hex_length:
        logger.info(f"  Proof hex length: {hex_lengths[0]} characters")
    else:
        logger.info(f"  Proof hex lengths observed: {sorted(set(hex_lengths))} characters")
    
    logger.info(f"Consistent SPK length: {consistent_spk_length}")
    if consistent_spk_length:
        logger.info(f"  SPK length: {spk_lengths[0]} bytes")
    else:
        logger.info(f"  SPK lengths observed: {sorted(set(spk_lengths))} bytes")
        
    logger.info(f"Consistent nullifier length: {consistent_nullifier_length}")
    if consistent_nullifier_length:
        logger.info(f"  Nullifier length: {nullifier_lengths[0]} bytes")
    else:
        logger.info(f"  Nullifier lengths observed: {sorted(set(nullifier_lengths))} bytes")
    
    return {
        'consistent_proof_length': consistent_proof_length,
        'consistent_hex_length': consistent_hex_length,
        'consistent_spk_length': consistent_spk_length,
        'consistent_nullifier_length': consistent_nullifier_length,
        'proof_lengths': proof_lengths,
        'hex_lengths': hex_lengths,
        'spk_lengths': spk_lengths,
        'nullifier_lengths': nullifier_lengths
    }

if __name__ == "__main__":
    results = test_proof_length_consistency(20)
    
    all_consistent = (
        results['consistent_proof_length'] and 
        results['consistent_hex_length'] and
        results['consistent_spk_length'] and
        results['consistent_nullifier_length']
    )
    
    if all_consistent:
        print("\n✅ CONSISTENT LENGTHS: All outputs have consistent length across runs")
        print(f"  Proof binary: {results['proof_lengths'][0]} bytes")
        print(f"  Proof hex: {results['hex_lengths'][0]} characters")
        print(f"  SPK: {results['spk_lengths'][0]} bytes")
        print(f"  Nullifier: {results['nullifier_lengths'][0]} bytes")
    else:
        print("\n⚠️ INCONSISTENT LENGTHS: Some outputs have varying lengths")
        
        if not results['consistent_proof_length']:
            print(f"  Proof binary lengths vary: {sorted(set(results['proof_lengths']))} bytes")
        
        if not results['consistent_hex_length']:
            print(f"  Proof hex lengths vary: {sorted(set(results['hex_lengths']))} characters")
            
        if not results['consistent_spk_length']:
            print(f"  SPK lengths vary: {sorted(set(results['spk_lengths']))} bytes")
            
        if not results['consistent_nullifier_length']:
            print(f"  Nullifier lengths vary: {sorted(set(results['nullifier_lengths']))} bytes")