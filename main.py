import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

# Encryption and Decryption Functions

# Generate a secure key from the password using SHA-256
def generate_key(password):
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
    return decrypted_data.decode()

# Handle client communication on the server
def handle_client(client_socket, password):
    try:
        # Receive the encrypted message or file
        encrypted_data = client_socket.recv(1024)
        
        # Decrypt the message
        key = generate_key(password)
        decrypted_message = decrypt_data(encrypted_data, key)
        
        # Process the message (print it out)
        print(f"Received: {decrypted_message}")
        
        # Send a response back to the client
        response = "Message received and decrypted successfully!"
        encrypted_response = encrypt_data(response, key)
        client_socket.send(encrypted_response)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

# Server Code to accept connections and handle clients
def start_server(host, port, password):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    
    print(f"Server is running and listening on {host}:{port}")
    
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection established with {client_address}")
        
        # Handle the client request
        handle_client(client_socket, password)

# Send a message to a specific server (or peer)
def send_message(host, port, message, password):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print(f"Connecting to {host}:{port}")
    try:
        client_socket.connect((host, port))
        
        # Encrypt the message
        key = generate_key(password)
        encrypted_message = encrypt_data(message, key)
        
        client_socket.send(encrypted_message)
        print("Message sent.")
        
        # Receive server response (if any)
        encrypted_response = client_socket.recv(1024)
        decrypted_response = decrypt_data(encrypted_response, key)
        print(f"Response from server: {decrypted_response}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

# Send a file to a specific server (or peer)
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
        
        # Receive server response (if any)
        encrypted_response = client_socket.recv(1024)
        decrypted_response = decrypt_data(encrypted_response, key)
        print(f"Response from server: {decrypted_response}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

# Main Client Loop
def start_client():
    host = input("Enter the server IP address: ")  # Input the IP address of the server
    port = 5001  # Use the same port as the server
    password = input("Enter the password for key generation: ")

    while True:
        print("\nOptions:")
        print("1. Send a message")
        print("2. Send a file")
        print("3. Exit")

        choice = input("Choose an option (1/2/3): ")

        if choice == '1':
            message = input("Enter the message to send: ")
            send_message(host, port, message, password)
        elif choice == '2':
            send_file(host, port, password)
        elif choice == '3':
            print("Exiting client.")
            break
        else:
            print("Invalid choice. Please try again.")

# Main Server and Client Entry Point
def main():
    role = input("Enter 'server' to run the server or 'client' to run the client: ").lower()
    
    if role == 'server':
        host = input("Enter the server IP address (or press Enter for localhost): ") or "127.0.0.1"
        port = 5001
        password = input("Enter the password for key generation: ")
        start_server(host, port, password)
    
    elif role == 'client':
        start_client()
    
    else:
        print("Invalid role. Please enter either 'server' or 'client'.")

if __name__ == "__main__":
    main()
