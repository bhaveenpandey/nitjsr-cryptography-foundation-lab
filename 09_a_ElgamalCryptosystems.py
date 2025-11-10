from Crypto.Util import number
import secrets

# --- Key Generation ---
def elgamal_keygen(bits=256):
    p = number.getPrime(bits)
    g = 2
    x = secrets.randbelow(p - 2) + 1  # private key
    h = pow(g, x, p)  # public key component
    return (p, g, h), x

# --- Encryption ---
def elgamal_encrypt(m, pubkey):
    p, g, h = pubkey
    y = secrets.randbelow(p - 2) + 1
    c1 = pow(g, y, p)
    s = pow(h, y, p)
    c2 = (m * s) % p
    return c1, c2

# --- Decryption ---
def elgamal_decrypt(cipher, privkey, p):
    c1, c2 = cipher
    s = pow(c1, privkey, p)
    s_inv = pow(s, -1, p)
    m = (c2 * s_inv) % p
    return m

# --- Example ---
if __name__ == "__main__":
    # Generate keys
    public_key, private_key = elgamal_keygen(256)
    p, g, h = public_key

    # Convert message to integer
    message = "HELLO".encode()
    m = int.from_bytes(message, 'big')
    print("Original message integer:", m)

    # Encrypt
    cipher = elgamal_encrypt(m, public_key)
    print("Ciphertext:", cipher)

    # Decrypt
    decrypted_int = elgamal_decrypt(cipher, private_key, p)
    decrypted_msg = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big')
    print("Decrypted message:", decrypted_msg.decode())
