# Server.py
import socket


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(5)
    print("Server is listening...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Got connection from {addr}")
        client_socket.send(bytes('Thank you for connecting', 'utf-8'))
        client_socket.close()


if __name__ == "__main__":
    start_server()