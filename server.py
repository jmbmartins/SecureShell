# server.py
import socket
import ssl
import bcrypt
import subprocess
import threading

# Dictionary to store users and their passwords
users = {}

# List of allowed commands that users can execute
allowed_commands = ['ls', 'pwd', 'whoami', 'date', 'uptime']

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

def handle_client(secure_socket):
    """
    Handles client requests. This includes registration, login, and command execution.
    """
    try:
        while True:
            command = secure_socket.recv(1024).decode()
            if command == 'quit':
                break
            elif command == 'register':
                username = secure_socket.recv(1024).decode()
                password = secure_socket.recv(1024).decode()
                message = register_user(username, password)
                secure_socket.send(bytes(message, 'utf-8'))
            elif command == 'login':
                username = secure_socket.recv(1024).decode()
                password = secure_socket.recv(1024).decode()
                # Check if the user exists and if the password is correct
                if username in users and bcrypt.checkpw(password.encode('utf-8'), users[username]):
                    secure_socket.send(bytes('Authentication successful', 'utf-8'))
                else:
                    secure_socket.send(bytes('Authentication failed', 'utf-8'))
            else:
                # Check if the command is allowed
                if command.split()[0] in allowed_commands:
                    # Execute the command and send the output back to the client
                    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
                    output, error = process.communicate()
                    secure_socket.send(output)
                else:
                    secure_socket.send(bytes('Command not allowed', 'utf-8'))
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

    while True:
        client_socket, address = secure_socket.accept()
        print(f"Connection from {address} has been established!")
        # Start a new thread to handle the client
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

if __name__ == "__main__":
    start_server()
