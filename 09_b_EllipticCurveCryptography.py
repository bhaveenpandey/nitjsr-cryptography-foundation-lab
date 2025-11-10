from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# --- Key generation for two users ---
priv1 = ec.generate_private_key(ec.SECP256R1(), default_backend())
pub1 = priv1.public_key()

priv2 = ec.generate_private_key(ec.SECP256R1(), default_backend())
pub2 = priv2.public_key()

print("Private key 1:", priv1.private_numbers().private_value)
print("Private key 2:", priv2.private_numbers().private_value)

# --- ECDH (Elliptic Curve Diffie-Hellman) shared secret ---
shared1 = priv1.exchange(ec.ECDH(), pub2)
shared2 = priv2.exchange(ec.ECDH(), pub1)
assert shared1 == shared2

# Derive symmetric key using HKDF
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
    backend=default_backend()
).derive(shared1)

print("\nECDH shared secret (hex):", shared1.hex())
print("Derived 256-bit key:", derived_key.hex())

# --- ECDSA (Elliptic Curve Digital Signature Algorithm) ---
message = b"Hello ECC "
signature = priv1.sign(message, ec.ECDSA(hashes.SHA256()))
r, s = decode_dss_signature(signature)

print("\nMessage:", message)
print("Signature (r, s):", (r, s))

# Verify signature
try:
    pub1.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    print("Signature verification: SUCCESS")
except Exception:
    print("Signature verification: FAIL")
