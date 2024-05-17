# server.py
import socket
import ssl
import bcrypt
import os
import getpass
import time
import platform
import threading
from datetime import timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Dictionary to store users and their passwords
users = {}

# List of allowed commands that users can execute
allowed_commands = ['ls', 'pwd', 'whoami', 'date', 'uptime']

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
    with open("server/private_key.pem", "wb") as private_key_file:
        private_key_file.write(pem_private_key)

    # Extract public key from private key and serialize to PEM format
    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Write public key to file
    with open("server/public_key.pem", "wb") as public_key_file:
        public_key_file.write(pem_public_key)

def load_keys():
    """
    Load RSA public and private keys from files.
    """
    from cryptography.hazmat.primitives import serialization

    # Load private key
    with open("server/private_key.pem", "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None
        )

    # Load public key
    with open("server/public_key.pem", "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(
            public_key_file.read()
        )
    
    # Load public key
    with open("client/public_key.pem", "rb") as public_key_file:
        client_public_key = serialization.load_pem_public_key(
            public_key_file.read()
        )

    return private_key, public_key, client_public_key

def generate_aes_key():
    """
    Generate a symmetric AES-GCM key.
    """
    return os.urandom(32)  # 256-bit key for AES-GCM

def encrypt_with_public_key(public_key, plaintext):
    """
    Encrypts data using RSA public key.
    """
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def sign_with_private_key(private_key, data):
    """
    Signs data using RSA private key.
    """
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def register_user(username, password):
    """
    Registers a new user with the provided password.
    The password is stored as a bcrypt hash for security.
    """
    if username in users:
        return 'Username already exists'
    else:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users[username] = hashed_password
        return 'Registration successful'

def execute_command(command):
    """
    Executes a command and returns the output.
    This function is platform-independent.
    """
    if command == 'ls':
        return '\n'.join(os.listdir('.'))
    elif command == 'pwd':
        return os.getcwd()
    elif command == 'whoami':
        return getpass.getuser()
    elif command == 'date':
        return time.ctime()
    elif command == 'uptime':
        if platform.system() == 'Windows':
            return 'Uptime not available on Windows'
        else:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
                uptime_string = str(timedelta(seconds = uptime_seconds))
                return uptime_string
    else:
        return 'Command not allowed'

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

def handle_client(secure_socket):
    """
    Handles client requests. This includes registration, login, and command execution.
    """
    logged_in = False
    
    try:
        private_key, public_key, client_public_key = load_keys()
        
        # Generate AES-GCM key
        aes_key = generate_aes_key()

        # Encrypt AES-GCM key with client's public key
        encrypted_aes_key = encrypt_with_public_key(client_public_key, aes_key)

        # Sign AES-GCM key with server's private key
        signature = sign_with_private_key(private_key, encrypted_aes_key)

        # Send encrypted AES-GCM key and signature to client
        secure_socket.send(encrypted_aes_key)
        secure_socket.send(signature)
        while True:
            command = decrypt_message(aes_key, secure_socket.recv(1024))
            if command == b'quit':
                break
            elif command == b'register':
                username = decrypt_message(aes_key, secure_socket.recv(1024)).decode()
                password = decrypt_message(aes_key, secure_socket.recv(1024)).decode()
                message = register_user(username, password)
                secure_socket.send(encrypt_message(aes_key, message.encode()))
            elif command == b'login':
                username = decrypt_message(aes_key, secure_socket.recv(1024)).decode()
                password = decrypt_message(aes_key, secure_socket.recv(1024)).decode()
                # Check if the user exists and if the password is correct
                if username in users and bcrypt.checkpw(password.encode('utf-8'), users[username]):
                    secure_socket.send(encrypt_message(aes_key, b'Authentication successful'))
                    logged_in = True
                else:
                    secure_socket.send(encrypt_message(aes_key, b'Authentication failed'))
            elif logged_in:
                # Check if the command is allowed and the user is logged in
                if command.split()[0] in allowed_commands:
                    # Execute the command and send the output back to the client
                    output = execute_command(command.decode())
                    secure_socket.send(encrypt_message(aes_key, output.encode()))
                else:
                    secure_socket.send(encrypt_message(aes_key, b'Command not allowed'))
            else:
                secure_socket.send(encrypt_message(aes_key, b'Please login first'))
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        secure_socket.close()

def start_server():
    """
    Starts the server, accepts connections, and starts threads to handle clients.
    """
    # Create an SSL context to encrypt the communication
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.pem")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure_socket = context.wrap_socket(server_socket, server_side=True)

    secure_socket.bind(('localhost', 12345))
    secure_socket.listen(5)

    if not os.path.exists("server/private_key.pem") or not os.path.exists("server/public_key.pem"):
        print("Server does not have RSA keys. They are currently being created in ./server")
        os.makedirs("server")
        generate_keys()
    

    while True:
        client_socket, address = secure_socket.accept()
        print(f"Connection from {address} has been established!")
        # Start a new thread to handle the client
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

if __name__ == "__main__":
    start_server()
