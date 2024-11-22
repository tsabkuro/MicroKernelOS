import os
from cryptography.fernet import Fernet

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

# Load the encryption key
def load_key():
    with open("encryption.key", "rb") as key_file:
        return key_file.read()

# Decrypt a file
def decrypt_file(filepath, fernet):
    with open(filepath, "rb") as file:
        encrypted = file.read()
    decrypted = fernet.decrypt(encrypted)
    with open(filepath, "wb") as decrypted_file:
        decrypted_file.write(decrypted)

# Recursively decrypt files in a directory
def decrypt_directory(directory, fernet):
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            # Decrypt all files except those in EXCEPTIONS
            if file not in EXCEPTIONS:
                decrypt_file(filepath, fernet)

# Main function
def main():
    print("Loading encryption key...")
    key = load_key()
    fernet = Fernet(key)

    current_directory = os.getcwd()

    print("Decrypting files...")
    decrypt_directory(current_directory, fernet)
    print("Decryption complete.")

if __name__ == "__main__":
    main()