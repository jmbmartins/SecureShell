# Client.py
import socket

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    while True:
        print("Enter 1 to register, 2 to login, or 0 to quit:")
        choice = input()
        if choice == '1':
            username = input("Enter username to register: ")
            password = input("Enter password: ")
            client_socket.send(bytes('register', 'utf-8'))
            client_socket.send(bytes(username, 'utf-8'))
            client_socket.send(bytes(password, 'utf-8'))
            print(client_socket.recv(1024).decode())
        elif choice == '2':
            username = input("Enter username to login: ")
            password = input("Enter password: ")
            client_socket.send(bytes('login', 'utf-8'))
            client_socket.send(bytes(username, 'utf-8'))
            client_socket.send(bytes(password, 'utf-8'))
            print(client_socket.recv(1024).decode())
        elif choice == '0':
            break
    client_socket.close()

if __name__ == "__main__":
    start_client()
