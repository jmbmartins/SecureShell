# Server.py
import socket
import ssl
import bcrypt
import subprocess
import threading

users = {}
allowed_commands = ['ls', 'pwd', 'date']  # Add your allowed commands here

def register_user(username, password):
    if username in users:
        return 'User already exists'
    else:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users[username] = hashed_password
        return 'User registered successfully'

def handle_client(secure_socket):
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
                if username in users and bcrypt.checkpw(password.encode('utf-8'), users[username]):
                    secure_socket.send(bytes('Authentication successful', 'utf-8'))
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
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.pem")

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', 12345))
        server_socket.listen(5)
        print("Server is listening...")

        while True:
            client_socket, addr = server_socket.accept()
            secure_socket = context.wrap_socket(client_socket, server_side=True)
            print(f"Got connection from {addr}")
            client_thread = threading.Thread(target=handle_client, args=(secure_socket,))
            client_thread.start()
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    start_server()
