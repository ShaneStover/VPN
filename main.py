import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import threading

# Global dictionary to keep track of connected clients per server
connected_clients = {}

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
def handle_client(client_socket, address, password, server_ip):
    try:
        # Receive the encrypted message or file
        encrypted_data = client_socket.recv(1024)
        
        # Decrypt the message
        key = generate_key(password)
        decrypted_message = decrypt_data(encrypted_data, key)
        
        # Add client to the list of connected clients for the server
        client_hash = hashlib.sha256(decrypted_message.encode()).hexdigest()
        if server_ip not in connected_clients:
            connected_clients[server_ip] = []
        connected_clients[server_ip].append(client_hash)

        # Process the message (print it out)
        print(f"Received from {client_hash}: {decrypted_message}")
        
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
        
        # Handle the client request in a separate thread
        threading.Thread(target=handle_client, args=(client_socket, client_address, password, host)).start()

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

# Client-side communication with server
def communicate_with_server(host, port, password):
    while True:
        print("\nOptions:")
        print("1. Send a message")
        print("2. Back to server list")
        print("3. Exit")

        choice = input("Choose an option (1/2/3): ")

        if choice == '1':
            message = input("Enter the message to send: ")
            send_message(host, port, message, password)
        elif choice == '2':
            print("Disconnecting from server.")
            break
        elif choice == '3':
            print("Exiting client.")
            exit()
        else:
            print("Invalid choice. Please try again.")

# Client-side code to choose a server and communicate with clients
def select_server_and_communicate():
    while True:
        print("\nAvailable Servers:")
        if not connected_clients:
            print("No servers available at the moment.")
            break
        for idx, (server_ip, clients) in enumerate(connected_clients.items()):
            print(f"SERVER#{idx + 1} - IP: {server_ip}")
            print("CONNECTED CLIENTS:")
            for client_hash in clients:
                print(f"- {client_hash}")
        
        selected_server_idx = input("\nSelect a server by number (or type |EXIT| to exit): ")
        
        if selected_server_idx.lower() == '|exit|':
            print("Exiting.")
            break
        
        try:
            selected_server_idx = int(selected_server_idx) - 1
            server_ip = list(connected_clients.keys())[selected_server_idx]
            print(f"Selected server: {server_ip}")
            
            # Ask for a client hash
            client_hash = input("Enter client cryptographic hash to communicate with: ")

            # Check if the client exists in the selected server
            if client_hash not in connected_clients[server_ip]:
                print("Client not found. Please try again.")
                continue
            
            # Now, communicate with the selected server
            print(f"Connecting to {server_ip}...")
            password = input("Enter the password for key generation: ")
            communicate_with_server(server_ip, 5001, password)
        
        except (ValueError, IndexError):
            print("Invalid server number. Please try again.")

# Main Server and Client Entry Point
def main():
    role = input("Enter 'server' to run the server or 'client' to run the client: ").lower()
    
    if role == 'server':
        host = input("Enter the server IP address (or press Enter for localhost): ") or "127.0.0.1"
        port = 5001
        password = input("Enter the password for key generation: ")
        start_server(host, port, password)
    
    elif role == 'client':
        select_server_and_communicate()
    
    else:
        print("Invalid role. Please enter either 'server' or 'client'.")

if __name__ == "__main__":
    main()
