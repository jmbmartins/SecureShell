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
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import pickle
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PublicFormat, PrivateFormat, NoEncryption

server_password = "password"

def generate_nonce(length=16):
    """
    Generate a random nonce of a given length.
    """
    return os.urandom(length)

def send_message(message, key, sockety):
    """
    Send a message to the socket, encrypted with the key, and then send a hash of the message.
    """
    message = message.encode('utf-8')
    sockety.send(encrypt_message(key, message))
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    sockety.send(encrypt_message(key, h.finalize()))

def receive_message(key, sockety):
    """
    Receive a message sent from send_message, decrypt it, and verify the hash.
    """
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

# Dictionary to store users and their passwords
users = {}

# List of allowed commands that users can execute
allowed_commands = ['help', 'ls', 'pwd', 'whoami', 'date', 'uptime']

def generate_keys():
    """
    Generate RSA public and private keys.
    """

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

#este gera as chaves de criptografia de EC
def generate_ecc_keys():
    
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Serialize private key to PEM format
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open("server/private_key.pem", "wb") as private_key_file:
        private_key_file.write(pem_private_key)

    # Serialize public key to PEM format
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

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

def register_user(username, password):
    """
    Registers a new user with the provided password.
    The password is stored as a bcrypt hash for security.
    """
    global users
    filename = hashlib.sha256(server_password.encode('utf-8')).hexdigest()
    with open( "server/" + filename+'.pickle', 'rb') as f:
        users = pickle.load(f)
    users = decrypt_message(server_password.ljust(32).encode('utf-8'), users)
    users = eval(users)
    if username in users:
        return 'Username already exists'
    else:
        
        users[username] = (password, 0)
        busers = str(users).encode('utf-8')
        busers = encrypt_message(server_password.ljust(32).encode('utf-8'), busers)
        with open("server/" + hashlib.sha256(server_password.encode('utf-8')).hexdigest()+'.pickle', 'wb') as f:
            pickle.dump(busers, f)
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
    elif command == 'help':
        return 'Available commands:' + allowed_commands
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

def generate_ecdh_parameters():
    return ec.generate_parameters(ec.SECP256R1())

def generate_ecdh_key_pair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def handle_client(secure_socket, dh_params, ecdh_params):
    """
    Handles client requests. This includes registration, login, and command execution.
    """
    logged_in = False
    
    try:
        private_key, public_key, client_public_key = load_keys()
        print("Keys loaded successfully.")
        
        # Generate AES-GCM key
        aes_key = generate_aes_key()
        print("AES-GCM key generated.")

        # Generate nonce
        nonce = generate_nonce()

        # Send nonce to client
        secure_socket.send(nonce)

        # Receive signed nonce from client
        signed_nonce = secure_socket.recv(1024)  # Use recv instead of receive

        # Verify signed nonce
        if not verify_signature(client_public_key, nonce, signed_nonce):
            print("Server Signature Authentication Protocol: Invalid signature")
            return
        print("Server Signature Authentication Protocol: Client Signature verified.")

        # Encrypt AES-GCM key with client's public key
        encrypted_aes_key = encrypt_with_public_key(client_public_key, aes_key)
        print("AES-GCM key encrypted with client's public key.")

        # Sign AES-GCM key with server's private key
        signature = sign_with_private_key(private_key, encrypted_aes_key)
        print("AES-GCM key signed with server's private key.")

        # Send encrypted AES-GCM key and signature to client
        secure_socket.send(encrypted_aes_key)
        secure_socket.send(signature)
        print("Encrypted AES-GCM key and signature sent to client.")

        dh = False
        dh_ec = False
        if(dh):
            dh_sk, dh_pk = generate_dh_key_pair(dh_params)
            secure_socket.send(serialize_public_key(dh_pk))
            client_dh_pk = deserialize_public_key(secure_socket.recv(1024))
            aes_key = derive_shared_key(dh_sk, client_dh_pk)
        if(dh_ec):
            ecdh_sk, ecdh_pk = generate_ecdh_key_pair(ecdh_params)
            secure_socket.send(serialize_public_key(ecdh_pk))
            ecclient_dh_pk = deserialize_public_key(secure_socket.recv(1024))
            aes_key = derive_shared_key(ecdh_sk, ecclient_dh_pk)

        while True:
            command = receive_message(aes_key, secure_socket)
            if command == 'quit':
                break
            elif command == 'register':
                username = receive_message(aes_key, secure_socket)
                password = receive_message(aes_key, secure_socket)
                message = register_user(username, password)
                send_message(message, aes_key, secure_socket)
                send_message(server_password, aes_key, secure_socket)
            elif command == 'login':
                username = receive_message(aes_key, secure_socket)
                challenge = str(users[username][1]) + str(os.urandom(16))
                salt = bcrypt.gensalt()
                send_message(challenge, aes_key, secure_socket)
                send_message(salt, aes_key, secure_socket)
                password = receive_message(aes_key, secure_socket)
                hash = bcrypt.hashpw((challenge+users[username][0]).encode('utf-8'), salt.encode('utf-8'))
                # Check if the user exists and if the password is correct
                if username in users and password == hash:
                    send_message('Authentication successful', aes_key, secure_socket)
                    challenge = receive_message(aes_key, secure_socket)
                    salt = receive_message(aes_key, secure_socket)
                    print(server_password)
                    answer = bcrypt.hashpw((challenge+server_password).encode('utf-8'), salt.encode('utf-8'))
                    send_message(answer, aes_key, secure_socket)
                    response = receive_message(aes_key, secure_socket)
                    if response == 'Server Authenticated':
                        users[username] = (users[username][0], users[username][1] + 1)
                        logged_in = True
                    else:
                        print("Server Authentication failed")
                else:
                    send_message('Authentication failed', aes_key, secure_socket)
            elif logged_in:
                print(command.split())
                # Check if the command is allowed and the user is logged in
                if command.split()[0] in allowed_commands:
                    # Execute the command and send the output back to the client
                    output = execute_command(command)
                    send_message(output, aes_key, secure_socket)
                else:
                    send_message('Command not allowed', aes_key, secure_socket)
            else:
                send_message('Please login first', aes_key, secure_socket)
    except Exception as e:
        print(f"An error occurred: {type(e).__name__}, {e}")
    finally:
        secure_socket.close()

def start_server():
    """
    Starts the server, accepts connections, and starts threads to handle clients.
    """

    ## este bloco é para chamar as funções da ECC 

    """
    encrypted_aes_key, ephemeral_public_key = encrypt_with_public_key(client_public_key, aes_key)
    signature = sign_with_private_key(private_key, encrypted_aes_key)

    secure_socket.send(ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    secure_socket.send(encrypted_aes_key)
    secure_socket.send(signature)

    """


    # Create an SSL context to encrypt the communication
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.pem")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure_socket = context.wrap_socket(server_socket, server_side=True)

    secure_socket.bind(('localhost', 12345))
    secure_socket.listen(5)
    secure_socket.settimeout(1)

    dh_params = generate_dh_parameters()
    ecdh_params = generate_ecdh_parameters()

    if not os.path.exists("server/private_key.pem") or not os.path.exists("server/public_key.pem"):
        print("Server does not have RSA keys. They are currently being created in ./server")
        os.makedirs("server")
        generate_keys()
    
    global server_password, users
    server_password = getpass.getpass("Enter server password: ")  # Use getpass for hidden input
    try:
        with open("server/" + hashlib.sha256(server_password.encode('utf-8')).hexdigest()+'.pickle', 'rb') as f:
            users = pickle.load(f)
            users  = decrypt_message(server_password.ljust(32).encode('utf-8'), users).decode('utf-8')
            users = eval(users)
    except FileNotFoundError:
        with open("server/" + hashlib.sha256(server_password.encode('utf-8')).hexdigest()+'.pickle', 'wb') as f:
            users = str(users).encode('utf-8')
            users = encrypt_message(server_password.ljust(32).encode('utf-8'), users)
            pickle.dump(users, f)
            print("Server does not have credentials file. It is currently being created. Please remember the filename: " + hashlib.sha256(server_password.encode('utf-8')).hexdigest()+'.pickle')
    while True:
        try:
            client_socket, address = secure_socket.accept()
            print(f"Connection from {address} has been established!")
            # Start a new thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, dh_params, ecdh_params))
            client_thread.start()
        except KeyboardInterrupt:
            print("\nbye bye")
            return;
        except socket.timeout:
            pass

if __name__ == "__main__":
    start_server();
