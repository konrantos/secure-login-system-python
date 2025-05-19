import os
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Generate key pair for digital signature using elliptic curves (ECDSA) with SECP256R1.
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


# Sign a message using a private key with ECDSA and SHA256.
def sign(private_key, message):
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


# Verify a digital signature using the public key.
def verify_signature(public_key, signature, message):
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except:
        return False


# Encrypt using AES symmetric algorithm in OFB mode.
def encrypt(key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv, ciphertext


# Decrypt a file using the same AES key that was used for encryption.
def decrypt(encrypted_file, decrypted_file, key):
    with open(encrypted_file, "rb") as encr_data:
        iv = encr_data.read(16)
        ciphertext = encr_data.read()
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    with open(decrypted_file, "wb") as decr_data:
        decr_data.write(plaintext)


# Save a private key to a .pem file.
def save_private_key(private_key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


# Load a private key from a file.
def load_private_key(filename):
    with open(filename, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)


# Save a public key to a .pem file.
def save_public_key(public_key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


# Load a public key from a file.
def load_public_key(filename):
    with open(filename, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())


# Verify user password using MD5 hash and salt.
def verify_password(password, hashed_password, salt):
    salted_password = password.encode() + salt
    hashed_input_password = hashlib.md5(salted_password).hexdigest()
    return hashed_input_password == hashed_password


# Login function with signature and decryption check.
def login(key):
    username = input("Username: ")
    password = input("Password: ")

    decrypt("encrypted_data.txt", "decrypted_data.txt", key)

    with open("decrypted_data.txt", "r") as data_file:
        data = data_file.read()

    public_key = load_public_key("public_key.pem")
    with open("data.txt.signature", "rb") as signature_file:
        signature = signature_file.read()

    if verify_signature(public_key, signature, data.encode("utf-8")):
        print("Digital signature is valid.")
        user_records = data.split("\n\n")
        user_found = False
        for record in user_records:
            lines = record.strip().split("\n")
            if len(lines) == 3:
                stored_username = lines[0].split(": ")[1].strip()
                stored_salt = bytes.fromhex(lines[1].split(": ")[1].strip())
                stored_hashed_password = lines[2].split(": ")[1].strip()
                if stored_username == username:
                    user_found = True
                    if verify_password(password, stored_hashed_password, stored_salt):
                        print("Password is correct.")
                        break
                    else:
                        print("Incorrect password. Try again.")
                        break
        if not user_found:
            print("Username not found. Try again.")
    else:
        print("Invalid digital signature.")
    try:
        os.remove("decrypted_data.txt")
    except FileNotFoundError:
        pass


# Main menu
while True:
    print("1. Create/Update 3 user records")
    print("2. Login")
    print("3. Exit")
    menu_choice = input("Select 1/2/3: ")

    if menu_choice == "1":
        key = os.urandom(32)
        private_key, public_key = generate_keys()
        save_private_key(private_key, "private_key.pem")
        save_public_key(public_key, "public_key.pem")

        with open("data.txt", "w") as user_file:
            for i in range(1, 4):
                print(f"User {i}:")
                username = input("Enter username: ")
                password = input("Enter password: ")
                salt = os.urandom(16)
                password_hash = hashlib.md5(password.encode() + salt).hexdigest()
                user_file.write(f"Username: {username}\n")
                user_file.write(f"Salt: {salt.hex()}\n")
                user_file.write(f"Password Hash: {password_hash}\n")
                user_file.write("\n")

        with open("data.txt", "r") as file:
            data = file.read().encode("utf-8")

        signature = sign(private_key, data)
        iv, ciphertext = encrypt(key, data)

        with open("data.txt.signature", "wb") as signature_file:
            signature_file.write(signature)
        with open("encrypted_data.txt", "wb") as file:
            file.write(iv + ciphertext)
        with open("aes_key.txt", "wb") as save_key:
            save_key.write(key)

    elif menu_choice == "2":
        with open("aes_key.txt", "rb") as get_key:
            key = get_key.read()
        login(key)

    elif menu_choice == "3":
        break
