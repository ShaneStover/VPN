import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import threading

# Encryption and Decryption Functions

# Generate a secure key from the password using SHA-256
def generate_key(password):
    return hashlib.sha256(password.encode()).digest()

# Encrypt the message or file content using AES
def encrypt_data(data, key):
    iv = os.urandom(16)  # Generate a random Initialization Vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted_data  # Prepend IV for decryption

# Decrypt the message or file content using AES
def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]  # Extract the IV from the beginning
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

# Encrypt a file
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = encrypt_data(file_data, key)
    return encrypted_data

# Decrypt a file
def decrypt_file(encrypted_data, key, output_file_path):
    decrypted_data = decrypt_data(encrypted_data, key)
    with open(output_file_path, 'wb') as file:
        file.write(decrypted_data)  # Save decrypted data as binary

# Handle client communication on the server
def handle_client(client_socket, password):
    try:
        while True:
            encrypted_data = client_socket.recv(1024)
            if not encrypted_data:
                break  # If no data is received, disconnect
            
            # Decrypt the message or file
            key = generate_key(password)
            decrypted_message = decrypt_data(encrypted_data, key)

            # Process the message or file (print it out for messages, save for files)
            if decrypted_message[:4] == b'FILE':
                # This indicates the received data is a file
                file_name = decrypted_message[4:].decode()  # Extract the file name from message
                with open(file_name, 'wb') as f:
                    file_data = client_socket.recv(1024)
                    f.write(file_data)
                print(f"Received file: {file_name}")
            else:
                # Normal message
                print(f"Received message: {decrypted_message.decode()}")

            # Ask the server to reply or send a file
            response = input("Enter a response or file path to send back (or type 'exit' to disconnect): ")
            if response.lower() == 'exit':
                print("Disconnecting...")
                break
            
            # Check if the response is a file path
            if os.path.isfile(response):
                # Encrypt and send the file
                encrypted_file = encrypt_file(response, key)
                client_socket.send(encrypted_file)
                print(f"File '{response}' sent.")
            else:
                # Encrypt and send the text message
                encrypted_response = encrypt_data(response.encode(), key)
                client_socket.send(encrypted_response)
                print(f"Message sent: {response}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

# Server Code to accept connections and handle clients
def start_server(host, port, password):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    
    print(f"\nServer is running and listening on {host}:{port}\n")
    
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection established with {client_address}")
        
        # Handle the client request in a separate thread
        threading.Thread(target=handle_client, args=(client_socket, password)).start()

# Send a message to a specific server (or peer)
def send_message(host, port, message, password):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print(f"\nConnecting to {host}:{port}...\n")
    try:
        client_socket.connect((host, port))
        
        # Encrypt the message
        key = generate_key(password)
        encrypted_message = encrypt_data(message.encode(), key)
        
        client_socket.send(encrypted_message)
        print("Message sent.")
        
        # Receive server response (if any)
        encrypted_response = client_socket.recv(1024)
        decrypted_response = decrypt_data(encrypted_response, key)
        print(f"Response from server: {decrypted_response.decode()}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

# Client-side communication with server
def communicate_with_server(host, port, password):
    while True:
        print("\nOptions:")
        print("1. Send a message")
        print("2. Send a file")
        print("3. Back to server selection")
        print("4. Exit")

        choice = input("Choose an option (1/2/3/4): ")

        if choice == '1':
            message = input("Enter the message to send: ")
            send_message(host, port, message, password)
        elif choice == '2':
            file_path = input("Enter the file path to send: ")
            if os.path.isfile(file_path):
                send_file(host, port, file_path, password)
            else:
                print("File not found!")
        elif choice == '3':
            print("Disconnecting from server.")
            break
        elif choice == '4':
            print("Exiting client.")
            exit()
        else:
            print("Invalid choice. Please try again.")

# Send a file to a server
def send_file(host, port, file_path, password):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect((host, port))
        
        # Send the file name first
        file_name = os.path.basename(file_path)
        encrypted_name = encrypt_data(f"FILE{file_name}".encode(), generate_key(password))
        client_socket.send(encrypted_name)
        
        # Read the file content and send it in chunks
        with open(file_path, 'rb') as file:
            while True:
                file_data = file.read(1024)
                if not file_data:
                    break
                encrypted_file_data = encrypt_data(file_data, generate_key(password))
                client_socket.send(encrypted_file_data)
        
        print(f"File '{file_name}' sent successfully.")
    except Exception as e:
        print(f"Error sending file: {e}")
    finally:
        client_socket.close()

# Client-side code to connect to a server by IP
def select_server_and_communicate():
    while True:
        print("\nEnter the server's IP address to connect:")
        server_ip = input("Server IP (or press Enter for localhost): ")
        if not server_ip:
            server_ip = "127.0.0.1"  # Default to localhost

        port = 5001  # The port where the server is listening
        password = input("Enter the password for key generation: ")
        
        # Attempt to communicate with the server
        print(f"Attempting to connect to server at {server_ip}:{port}...\n")
        communicate_with_server(server_ip, port, password)

# Main Server and Client Entry Point
def main():
    role = input("\nEnter 'server' to run the server or 'client' to run the client: ").lower()
    
    if role == 'server':
        host = input("\nEnter the server IP address (or press Enter for localhost): ") or "127.0.0.1"
        port = 5001
        password = input("\nEnter the password for key generation: ")
        start_server(host, port, password)
    
    elif role == 'client':
        select_server_and_communicate()
    
    else:
        print("Invalid role. Please enter either 'server' or 'client'.")

if __name__ == "__main__":
    main()
