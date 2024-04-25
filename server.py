# Server.py
import socket
import bcrypt

# A dictionary to store username and hashed password
users = {
    "user1": bcrypt.hashpw("password1".encode('utf-8'), bcrypt.gensalt()),
    "user2": bcrypt.hashpw("password2".encode('utf-8'), bcrypt.gensalt()),
    # Add more users as needed
}

def register_user(username, password):
    if username in users:
        return 'Username already exists'
    else:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users[username] = hashed_password
        return 'User registered successfully'

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(5)
    print("Server is listening...")
    
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Got connection from {addr}")
        command = client_socket.recv(1024).decode()
        if command == 'register':
            username = client_socket.recv(1024).decode()
            password = client_socket.recv(1024).decode()
            message = register_user(username, password)
            client_socket.send(bytes(message, 'utf-8'))
        elif command == 'login':
            username = client_socket.recv(1024).decode()
            password = client_socket.recv(1024).decode()
            if username in users and bcrypt.checkpw(password.encode('utf-8'), users[username]):
                client_socket.send(bytes('Authentication successful', 'utf-8'))
            else:
                client_socket.send(bytes('Authentication failed', 'utf-8'))
        client_socket.close()

if __name__ == "__main__":
    start_server()
