# client.py
import socket
import ssl

def start_client():
    """
    Starts the client, connects to the server, and handles user input.
    """
    secure_socket = None
    try:
        # Create an SSL context to encrypt the communication
        context = ssl.create_default_context()
        context.load_verify_locations(cafile="server-cert.pem")

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secure_socket = context.wrap_socket(client_socket, server_side=False, server_hostname='localhost')

        secure_socket.connect(('localhost', 12345))

        while True:
            print("1. Register")
            print("2. Login")
            print("0. Quit")
            choice = input("Enter your choice: ")
            if choice == '1':
                # Register a new user
                username = input("Enter username to register: ")
                password = input("Enter password: ")
                secure_socket.send(bytes('register', 'utf-8'))
                secure_socket.send(bytes(username, 'utf-8'))
                secure_socket.send(bytes(password, 'utf-8'))
                print(secure_socket.recv(1024).decode())
            elif choice == '2':
                # Login with an existing user
                username = input("Enter username to login: ")
                password = input("Enter password: ")
                secure_socket.send(bytes('login', 'utf-8'))
                secure_socket.send(bytes(username, 'utf-8'))
                secure_socket.send(bytes(password, 'utf-8'))
                response = secure_socket.recv(1024).decode()
                print(response)
                if response == 'Authentication successful':
                    while True:
                        # Execute a command
                        command = input("Enter a command to execute (or 'quit' to logout): ")
                        if command == 'quit':
                            break
                        secure_socket.send(bytes(command, 'utf-8'))
                        response = secure_socket.recv(1024).decode()
                        if response == 'Command not allowed' or response == 'Please login first':
                            print("The command you entered is not allowed or you are not logged in.")
                        else:
                            print(response)
            elif choice == '0':
                # Quit the client
                secure_socket.send(bytes('quit', 'utf-8'))
                break
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if secure_socket is not None:
            secure_socket.close()

if __name__ == "__main__":
    start_client()
