# Client.py
import socket

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    print(client_socket.recv(1024).decode())
    client_socket.close()

if __name__ == "__main__":
    start_client()