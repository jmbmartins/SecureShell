#client.py
import socket
import ssl
import os
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import bcrypt
import hashlib
import getpass  # Import getpass module

def send_message(message, key, sockety):
    message = message.encode('utf-8')
    sockety.send(encrypt_message(key, message))
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    sockety.send(encrypt_message(key, h.finalize()))

def receive_message(key, sockety):
    response = decrypt_message(key, sockety.recv(1024))
    response_hash = decrypt_message(key, sockety.recv(1024))
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(response)
    hash_is_good = True
    try:
        h.verify(response_hash)
    except hmac.InvalidSignature:
        hash_is_good = False

    if hash_is_good:
        return response.decode('utf-8')
    else:
        print("CLAIRE WARNING")
        return "CLAIRE WARNING"


def generate_keys():
    """
    Generate RSA public and private keys.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize private key to PEM format
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Write private key to file
    with open("client/private_key.pem", "wb") as private_key_file:
        private_key_file.write(pem_private_key)

    # Extract public key from private key and serialize to PEM format
    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Write public key to file
    with open("client/public_key.pem", "wb") as public_key_file:
        public_key_file.write(pem_public_key)

def load_keys():
    """
    Load RSA public and private keys from files.
    """
    from cryptography.hazmat.primitives import serialization

    # Load private key
    with open("client/private_key.pem", "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None
        )

    # Load public key
    with open("client/public_key.pem", "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(
            public_key_file.read()
        )

    with open("server/public_key.pem", "rb") as public_key_file:
        server_public_key = serialization.load_pem_public_key(
            public_key_file.read()
        )

    return private_key, public_key, server_public_key

def encrypt_message(key, message):
    """
    Encrypts a message using AES-GCM.
    """
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def decrypt_message(key, ciphertext):
    """
    Decrypts a message using AES-GCM.
    """
    iv = ciphertext[:16]
    tag = ciphertext[16:32]
    ciphertext = ciphertext[32:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def encrypt_with_public_key(key, message):
    """
    Encrypts a message using RSA.
    """
    ciphertext = key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_with_private_key(key, ciphertext):
    """
    Decrypts a message using RSA.
    """
    plaintext = key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def verify_signature(public_key, signature, data):
    """
    Verifies a signature using RSA public key.
    """
    public_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def start_client():
    """
    Starts the client, connects to the server, and handles user input.
    """
    secure_socket = None
    try:

        if not os.path.exists("client/private_key.pem") or not os.path.exists("client/public_key.pem"):
            print("Client does not have RSA keys. They are currently being created in ./client")
            os.makedirs("client")
            generate_keys()

        # Load keys
        private_key, public_key, server_public_key = load_keys()

        # Create an SSL context to encrypt the communication
        context = ssl.create_default_context()
        context.load_verify_locations(cafile="server-cert.pem")

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secure_socket = context.wrap_socket(client_socket, server_side=False, server_hostname='localhost')

        secure_socket.connect(('localhost', 12345))

        print("Connected to server.")
        print("Negotiated Cipher:", secure_socket.cipher())
        print("Negotiated SSL/TLS Protocol:", secure_socket.version())

        # Receive encrypted AES-GCM key and signature from server
        encrypted_aes_key = secure_socket.recv(1024)
        signature = secure_socket.recv(1024)

        # Verify the signature using the server's public key
        verify_signature(server_public_key, signature, encrypted_aes_key)

        # Decrypt the AES-GCM key using the client's private key
        aes_key = decrypt_with_private_key(private_key, encrypted_aes_key)
        print("Here")

        while True:
            print("1. Register")
            print("2. Login")
            print("0. Quit")
            choice = input("Enter your choice: ")
            if choice == '1':
                # Register a new user
                username = input("Enter username to register: ")
                password = getpass.getpass("Enter password: ")  # Use getpass for hidden input
                send_message('register', aes_key, secure_socket)
                send_message(username, aes_key, secure_socket)
                send_message(password, aes_key, secure_socket)
                print(receive_message(aes_key, secure_socket))
            elif choice == '2':
                # Login with an existing user
                username = input("Enter username to login: ")
                password = getpass.getpass("Enter password: ")  # Use getpass for hidden input
                send_message('login', aes_key, secure_socket)
                send_message(username, aes_key, secure_socket)
                send_message(password, aes_key, secure_socket)
                response = receive_message(aes_key, secure_socket)
                print(response)
                if response == 'Authentication successful':
                    while True:
                        # Execute a command
                        command = input("Enter a command to execute (or 'quit' to logout): ")
                        if command == 'quit':
                            break
                        send_message(command, aes_key, secure_socket)
                        response = receive_message(aes_key, secure_socket)
                        if response == 'Command not allowed' or response == 'Please login first':
                            print("The command you entered is not allowed or you are not logged in.")
                        else:
                            print(response)
            elif choice == '0':
                # Quit the client
                send_message('quit', aes_key, secure_socket)
                break
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if secure_socket is not None:
            secure_socket.close()

if __name__ == "__main__":
    start_client()
