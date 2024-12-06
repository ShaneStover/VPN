import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import hashlib

# Encryption and Decryption Functions

# Generate a secure key from the password using SHA-256
def generate_key(password):
    # Use SHA-256 to hash the password and generate a key
    return hashlib.sha256(password.encode()).digest()

# Encrypt the message or file content using AES
def encrypt_data(data, key):
    iv = os.urandom(16)  # Generate a random Initialization Vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return iv + encrypted_data  # Prepend IV for decryption

# Decrypt the message or file content using AES
def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]  # Extract the IV from the beginning
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

# Server Code
def start_server(host, port, password):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server is running and listening on {host}:{port}")
    
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection established with {client_address}")
        
        # Receive the encrypted data
        data = client_socket.recv(1024)
        
        # Decrypt the data
        key = generate_key(password)
        decrypted_data = decrypt_data(data, key)
        
        # Check if the decrypted data is text or file
        try:
            # Try to decode as a text message
            decrypted_message = decrypted_data.decode()
            print(f"Decrypted message: {decrypted_message}")
        except UnicodeDecodeError:
            # If it fails to decode, assume it's a file and save it
            print("Received file data. Saving to 'received_file'")
            with open("received_file", "wb") as file:
                file.write(decrypted_data)
        
        client_socket.close()

# Client Code
def send_message(host, port, message, password):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print(f"Connecting to {host}:{port}")  # Debugging line
    try:
        client_socket.connect((host, port))
        
        # Encrypt the message
        key = generate_key(password)
        encrypted_message = encrypt_data(message, key)
        
        client_socket.send(encrypted_message)
        print("Message sent.")
    except ConnectionRefusedError:
        print("Connection refused. Ensure the server is running and the correct port is being used.")
    finally:
        client_socket.close()

# Client File Transfer Code (Optional)
def send_file(host, port, password):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    file_path = input("Enter the full file path to send: ")
    if not os.path.isfile(file_path):
        print("Invalid file path. Please try again.")
        return

    print(f"Connecting to {host}:{port}")
    try:
        client_socket.connect((host, port))
        
        # Read and encrypt the file
        key = generate_key(password)
        with open(file_path, 'rb') as file:
            file_data = file.read()
        encrypted_file_data = encrypt_data(file_data.decode(), key)
        
        client_socket.send(encrypted_file_data)
        print(f"File {file_path} sent.")
    except ConnectionRefusedError:
        print("Connection refused. Ensure the server is running and the correct port is being used.")
    finally:
        client_socket.close()

# Main function to start the server or client
def main():
    action = input("Enter 'server' to run the server or 'client' to run the client: ").lower()

    if action == "server":
        host = input("Enter the server IP address (or press Enter for localhost): ") or '0.0.0.0'  # '0.0.0.0' will allow all devices on the local network
        port = 5001  # Use a port number that is free
        password = input("Enter a password for key generation: ")
        start_server(host, port, password)
    
    elif action == "client":
        host = input("Enter the server IP address: ")  # Input the IP address of the server
        port = 5001  # Use the same port as the server
        message = input("Enter the message to send: ")
        password = input("Enter the password for key generation: ")
        send_message(host, port, message, password)
    
    else:
        print("Invalid choice. Please enter either 'server' or 'client'.")

if __name__ == "__main__":
    main()
