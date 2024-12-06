import socket
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Function to generate a key based on the password
def generate_key(password):
    # Create a key from the password using SHA-256 hashing
    return hashlib.sha256(password.encode()).digest()

# Encrypt the data using AES
def encrypt_data(data, key):
    iv = os.urandom(16)  # Random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return iv + encrypted_data  # Prepend IV to the encrypted data

# Decrypt the data using AES
def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]  # Extract the IV from the encrypted data
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data.decode()

# Encrypt a file
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = encrypt_data(file_data.decode(), key)  # Convert binary to string for encryption
    with open(file_path + ".enc", 'wb') as file:
        file.write(encrypted_data)

# Decrypt a file
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = decrypt_data(encrypted_data, key)
    with open(file_path.replace(".enc", ".dec"), 'wb') as file:
        file.write(decrypted_data.encode())  # Save decrypted data as bytes

# Server code to receive files and messages
def start_server(host, port, password):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server started on {host}:{port}")
    
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection established with {client_address}")
        
        # Receive the encrypted data
        data = client_socket.recv(1024)
        
        # Decrypt the data
        key = generate_key(password)
        decrypted_message = decrypt_data(data, key)
        
        print(f"Decrypted message: {decrypted_message}")
        
        client_socket.close()

# Client code to send files and messages
def send_message(host, port, message, password):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    
    # Encrypt the message
    key = generate_key(password)
    encrypted_message = encrypt_data(message, key)
    
    client_socket.send(encrypted_message)
    print("Message sent.")
    
    client_socket.close()

# File transfer function
def send_file(host, port, file_path, password):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    
    # Read and encrypt the file
    key = generate_key(password)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_file_data = encrypt_data(file_data.decode(), key)  # Convert binary to string for encryption
    
    client_socket.send(encrypted_file_data)
    print(f"File {file_path} sent.")
    
    client_socket.close()

# Main function to start server or client
def main():
    mode = input("Enter 'server' to run the server or 'client' to run the client: ").strip().lower()

    if mode == 'server':
        host = '127.0.0.1'
        port = 1923
        password = input("Enter a password for key generation: ")
        start_server(host, port, password)
    elif mode == 'client':
        host = '127.0.0.1'
        port = 1293
        message = input("Enter a message to send: ")
        password = input("Enter a password for key generation: ")
        send_message(host, port, message, password)
    else:
        print("Invalid input! Please enter 'server' or 'client'.")

if __name__ == "__main__":
    main()
