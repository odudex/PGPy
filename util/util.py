from PGPy.pgpy.packet.fields import ECDSASignature, MPI


def bytes_to_ecdsasig(sig_bytes: bytes) -> ECDSASignature:
    if len(sig_bytes) != 64:
        raise ValueError("ECDSA signature must be 64 bytes")
    
    # Split into r and s components
    
    # secp256r1 is big endian
    # r = int.from_bytes(sig_bytes[:32], 'big')
    # s = int.from_bytes(sig_bytes[32:], 'big')
    
    # secp256k1 is little endian
    r = int.from_bytes(sig_bytes[:32], 'little')
    s = int.from_bytes(sig_bytes[32:], 'little')
    
    # Create ECDSASignature object
    sig = ECDSASignature()
    sig.r = MPI(r)
    sig.s = MPI(s)
    return sig