import hashlib

def generate_sha128_like_hash(text):
    sha256_hash = hashlib.sha256(text.encode()).hexdigest()
    return sha256_hash[:32]  # 32 hex chars = 128 bits

# Example usage
input_text = input("Enter text to hash: ")
print("Pseudo SHA-128 Hash:", generate_sha128_like_hash(input_text))
