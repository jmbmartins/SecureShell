# Client.py

# Imports
import socket
import ssl
import os
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import bcrypt
import hashlib
import getpass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import ec

# Function that encapsulates the action of sending an encrypted message and its hmac
def send_message(message, key, sockety):
    message = message.encode('utf-8')
    sockety.send(encrypt_message(key, message))
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    sockety.send(encrypt_message(key, h.finalize()))

# Function that encapsulates the action of receiving an encrypted message and its hmac, while verifying it
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

# Function that generates and saves a pair of RSA keys in memory
def generate_keys():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open("client/private_key.pem", "wb") as private_key_file:
        private_key_file.write(pem_private_key)

    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("client/public_key.pem", "wb") as public_key_file:
        public_key_file.write(pem_public_key)

# Function that loads the client's RSA keys from persistent memory
def load_keys():
    from cryptography.hazmat.primitives import serialization

    with open("client/private_key.pem", "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None
        )

    with open("client/public_key.pem", "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(
            public_key_file.read()
        )

    with open("server/public_key.pem", "rb") as public_key_file:
        server_public_key = serialization.load_pem_public_key(
            public_key_file.read()
        )

    return private_key, public_key, server_public_key

# Function that encrypts a message with symmetric cryptography
def encrypt_message(key, message):
    """
    Encrypts a message using AES-GCM.
    """
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

# Function that decrypts a message with symmetric cryptography
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

# Function that encrypts a message with a given public key
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

def sign_with_private_key(private_key, message):
    """
    Sign the message with the private key.
    """
    # Convert the message to bytes if it's not already
    if not isinstance(message, bytes):
        message = message.encode()

    # Create a signature of the message
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    """
    Verify the signature of the message with the public key.
    """
    # Convert the message to bytes if it's not already
    if not isinstance(message, bytes):
        message = message.encode()

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    
def generate_dh_parameters():
    return dh.generate_parameters(generator=2, key_size=2048)

def generate_dh_key_pair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    return load_pem_public_key(public_key_bytes)

def generate_ecdh_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


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
        print("Keys loaded successfully.")

        # Create an SSL context to encrypt the communication
        context = ssl.create_default_context()
        context.load_verify_locations(cafile="server-cert.pem")

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secure_socket = context.wrap_socket(client_socket, server_side=False, server_hostname='localhost')

        secure_socket.connect(('localhost', 12345))

        print("Connected to server.")
        print("Negotiated Cipher:", secure_socket.cipher())
        print("Negotiated SSL/TLS Protocol:", secure_socket.version())

        # Receive nonce from server
        nonce = secure_socket.recv(1024)

        # Sign nonce with client's private key
        signed_nonce = sign_with_private_key(private_key, nonce)

        # Send signed nonce to server
        secure_socket.send(signed_nonce)

        # Receive encrypted AES-GCM key and signature from server
        encrypted_aes_key = secure_socket.recv(1024)
        signature = secure_socket.recv(1024)
        print("Encrypted AES-GCM key and signature received from server.")

        # Verify the signature using the server's public key
        if not verify_signature(server_public_key, encrypted_aes_key, signature):
            print("Client Signature Authentication Protocol: Invalid signature.")
            return
        print("Client Signature Authentication Protocol: Server Signature verified.")

        # Decrypt the AES-GCM key using the client's private key
        aes_key = decrypt_with_private_key(private_key, encrypted_aes_key)
        print("AES-GCM key decrypted with client's private key.")

        dh = False
        dh_ec = False
        if(dh):
            dh_params = generate_dh_parameters()
            dh_sk, dh_pk = generate_dh_key_pair(dh_params)
            secure_socket.send(serialize_public_key(dh_pk))
            client_dh_pk = deserialize_public_key(secure_socket.recv(1024))
            aes_key = derive_shared_key(dh_sk, client_dh_pk)
        if(dh_ec):
            ecdh_sk, ecdh_pk = generate_ecdh_key_pair()
            secure_socket.send(serialize_public_key(ecdh_pk))
            ecclient_dh_pk = deserialize_public_key(secure_socket.recv(1024))
            aes_key = derive_shared_key(ecdh_sk, ecclient_dh_pk)

        server_password = ""
        id = 0
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
                server_password = receive_message(aes_key, secure_socket)
                with open("client/.txt", "w") as f:
                    f.write(server_password)
            elif choice == '2':
                # Login with an existing user
                username = input("Enter username to login: ")
                password = getpass.getpass("Enter password: ")  # Use getpass for hidden input
                send_message('login', aes_key, secure_socket)
                send_message(username, aes_key, secure_socket)
                challenge = receive_message(aes_key, secure_socket)
                salt = receive_message(aes_key, secure_socket)
                answer = bcrypt.hashpw((challenge+password).encode('utf-8'), salt.encode('utf-8'))
                send_message(answer, aes_key, secure_socket)
                response = receive_message(aes_key, secure_socket)
                print(response)
                if response == 'Authentication successful':
                    challenge = str(id) + str(os.urandom(16))
                    salt = bcrypt.gensalt()
                    send_message(challenge, aes_key, secure_socket)
                    send_message(salt, aes_key, secure_socket)
                    password = receive_message(aes_key, secure_socket)
                    print("password:" + server_password)
                    hash = bcrypt.hashpw((challenge+server_password).encode('utf-8'), salt.encode('utf-8'))
                    if hash == password:
                        print("Server authenticated")
                        id += 1
                        send_message('Server Authenticated', aes_key, secure_socket)
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
                    else:
                        print("Server not authenticated")
            elif choice == '0':
                # Quit the client
                send_message('quit', aes_key, secure_socket)
                break
    except Exception as e:
        print(f"An error occurred: {type(e).__name__}, {e}")
    finally:
        if secure_socket is not None:
            secure_socket.close()

if __name__ == "__main__":
    start_client()
