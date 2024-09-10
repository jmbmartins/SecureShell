# SecureShell 

## Introduction

This project aims to build a client/server system that mimics Secure Shell (SSH). The server application accepts connections from client applications, authenticates registered users, establishes session keys, and allows clients to submit commands that are typically used in an SSH session. Here are the commands detailed in the text:

-   **ls**: Lists the contents of the current directory.
-   **pwd**: Prints the current working directory.
-   **whoami**: Returns the username of the current user.
-   **date**: Returns the current date and time.
-   **uptime**: Returns the system uptime (not available on Windows).
-   **help**: Lists the available commands.

These commands are used to interact with the host machine securely after establishing a connection and authenticating the user. The focus is on **secure communication rather than the breadth of commands**.

### Basic Features

1.  **Secure client authentication**:
    -   **bcrypt**: Password hashing for secure storage and verification of user credentials.
    -   **Digital Signatures**: Signing and verifying messages to ensure authenticity.
2.  **Encrypted communication between clients and server**:
    -   **SSL/TLS**: Secure communication over a network.
    -   **AES-GCM**: Symmetric encryption and decryption for message confidentiality.
3.  **New session keys generated for each session**:
    -   **Diffie-Hellman (DH)**: Key exchange to generate new session keys.
    -   **ECDH (Elliptic Curve Diffie-Hellman)**: Key exchange with elliptic curves for generating session keys.
4.  **Message authentication between clients and server**:
    -   **HMAC**: Message integrity and authenticity to ensure messages are not tampered with.

### Advanced Features

1.  **Cross-platform support**:
    -   **Platform-independent code**: Use of Python libraries and functions that work across different operating systems.
2.  **Strong authentication mechanisms**:
    -   **bcrypt**: Password hashing for secure authentication.
    -   **Digital Signatures**: Ensuring the authenticity of messages and users.
3.  **Mutual authentication (client and server)**:
    -   **Digital Signatures**: Both client and server sign and verify messages to authenticate each other.
    -   **SSL/TLS**: Provides mutual authentication through certificates.
4.  **Multiple key exchange mechanisms (symmetric and asymmetric)**:
    -   **Diffie-Hellman (DH)**: Key exchange for symmetric keys.
    -   **ECDH (Elliptic Curve Diffie-Hellman)**: Key exchange with elliptic curves.
    -   **RSA**: Asymmetric encryption and decryption for key exchange.
5.  **Digital signature for message authentication**:
    -   **Digital Signatures**: Signing and verifying messages to ensure they are from a legitimate source.
6.  **Use of elliptic curve cryptography instead of RSA**:
    -   **ECDH (Elliptic Curve Diffie-Hellman)**: Key exchange using elliptic curves.
    -   **Elliptic Curve Digital Signature Algorithm (ECDSA)**: For signing and verifying messages.

## Demonstration

Watch the demonstration video on [YouTube](https://www.youtube.com/watch?v=E1cNaFfcUis).

## Project Schema

View the project schema [here](https://github.com/jmbmartins/SecureShell/blob/main/projectschema.png).
