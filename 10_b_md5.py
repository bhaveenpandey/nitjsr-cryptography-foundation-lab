import hashlib

# Function to generate MD5 hash for a string
def generate_md5_hash(text):
    # Encode the string to bytes, then create the MD5 hash
    md5_hash = hashlib.md5(text.encode())
    # Return the hexadecimal representation of the hash
    return md5_hash.hexdigest()

# Example usage
input_text = input("Enter text to hash: ")
print("MD5 Hash:", generate_md5_hash(input_text))
