import os
from cryptography.fernet import Fernet

# Specify files/folders to exclude from encryption (relative paths from the script's directory)
EXCEPTIONS = {
    ".git",
    "README.md",
    ".gitignore",
    "encryption.py",
    "decryption.py",
    "lib/util",
    "lib/mm/mm.c",
    "lib/aos/paging.c",
    "lib/grading/tests/test_paging.c",
    "lib/hashtable/hashtable.c",
    "encryption.key"
}

# Generate an encryption key
def generate_key():
    key = Fernet.generate_key()
    with open("encryption.key", "wb") as key_file:
        key_file.write(key)
    return key

# Load the existing encryption key
def load_key():
    with open("encryption.key", "rb") as key_file:
        return key_file.read()

# Encrypt a file
def encrypt_file(filepath, fernet):
    with open(filepath, "rb") as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(filepath, "wb") as encrypted_file:
        encrypted_file.write(encrypted)

# Check if a file or directory is excluded
def is_excluded(filepath, script_dir):
    # Normalize paths for comparison
    relative_path = os.path.relpath(filepath, script_dir)
    for exception in EXCEPTIONS:
        if relative_path == exception or relative_path.startswith(exception + os.sep):
            return True
    return False

# Recursively encrypt files in a directory
def encrypt_directory(directory, fernet, script_dir):
    for root, dirs, files in os.walk(directory):
        # Remove excluded directories
        dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root, d), script_dir)]
        for file in files:
            filepath = os.path.join(root, file)
            # Skip excluded files
            if not is_excluded(filepath, script_dir):
                encrypt_file(filepath, fernet)

# Main function
def main():
    script_dir = os.path.abspath(os.path.dirname(__file__))

    # Generate a key if it doesn't exist
    if not os.path.exists("encryption.key"):
        print("Generating encryption key...")
        key = generate_key()
    else:
        print("Loading existing encryption key...")
        key = load_key()

    fernet = Fernet(key)

    print("Encrypting files...")
    encrypt_directory(script_dir, fernet, script_dir)
    print("Encryption complete.")

if __name__ == "__main__":
    main()