import socket
import threading
import hashlib
import json
import os
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Constants for Diffie-Hellman
P = 23  # Prime number
G = 5   # Generator

# File to store user credentials
CRED_FILE = "creds.txt"
clients = {}  # Dictionary to track clients: {username: (socket, aes_key)}


def diffie_hellman_generate_key():
    private_key = secrets.randbelow(P)
    public_key = pow(G, private_key, P)
    return private_key, public_key


def diffie_hellman_compute_shared_key(private_key, other_public_key):
    return pow(other_public_key, private_key, P)


def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    return iv + encrypted_message


def aes_decrypt(encrypted_message, key):
    iv = encrypted_message[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message[AES.block_size:]), AES.block_size)
    return decrypted_message.decode()


def save_credentials(username, email, hashed_password, salt):
    with open(CRED_FILE, "a") as file:
        json.dump({"username": username, "email": email, "password": hashed_password, "salt": salt.hex()}, file)
        file.write("\n")


def load_credentials():
    credentials = {}
    if os.path.exists(CRED_FILE):
        with open(CRED_FILE, "r") as file:
            for line in file:
                user_data = json.loads(line.strip())
                credentials[user_data["username"]] = user_data
    return credentials


def broadcast_message(sender_username, message, aes_key):
    # Relay message to the specified client
    if sender_username in clients:
        sender_socket, _ = clients[sender_username]
        sender_socket.sendall(aes_encrypt(message, aes_key))


def handle_client(client_socket, client_address):
    credentials = load_credentials()

    # Diffie-Hellman key exchange
    server_private_key, server_public_key = diffie_hellman_generate_key()
    
    client_socket.sendall(str(server_public_key).encode())
    client_public_key = int(client_socket.recv(1024).decode())
    shared_secret = diffie_hellman_compute_shared_key(server_private_key, client_public_key)
    aes_key = hashlib.sha256(str(shared_secret).encode()).digest()[:16]  # AES-128 key


    # Receive action type (register or login)
    action_type = aes_decrypt(client_socket.recv(1024), aes_key)

    if action_type == "register":
        reg_data = json.loads(aes_decrypt(client_socket.recv(1024), aes_key))
        username, email, password = reg_data["username"], reg_data["email"], reg_data["password"]

        if username in credentials:
            client_socket.sendall(aes_encrypt("Username already exists. Try again.", aes_key))
        else:
            salt = secrets.token_bytes(16)
            hashed_password = hashlib.sha256(password.encode() + salt).hexdigest()
            save_credentials(username, email, hashed_password, salt)
            client_socket.sendall(aes_encrypt("Registration successful.", aes_key))

    elif action_type == "login":
        login_data = json.loads(aes_decrypt(client_socket.recv(1024), aes_key))
        username, password = login_data["username"], login_data["password"]

        if username in credentials:
            salt = bytes.fromhex(credentials[username]["salt"])
            stored_hash = credentials[username]["password"]
            hashed_input = hashlib.sha256(password.encode() + salt).hexdigest()
            if hashed_input == stored_hash:
                client_socket.sendall(aes_encrypt("Login successful. Start chatting.", aes_key))
                clients[username] = (client_socket, aes_key)
                
                while True:
                    encrypted_data = client_socket.recv(1024)
                    if encrypted_data:
                        data = json.loads(aes_decrypt(encrypted_data, aes_key))
                        recipient = data["recipient"]
                        message = data["message"]
                        print(f"Sender's AES Key: {aes_key.hex()}")

                        if recipient in clients:
                            recipient_socket, recipient_key = clients[recipient]
                            print(f"Recipient's AES Key: {recipient_key.hex()}")
                            print(f"Message received from {username}: {message} (Recipient: {recipient})")
                            
                            # Send message to recipient
                            print(f"Sending message to {recipient}...")
                            recipient_socket.sendall(aes_encrypt(f"{username}: {message}", recipient_key))
                        else:
                            print(f"Recipient {recipient} not online.")
                            client_socket.sendall(aes_encrypt("Recipient not online.", aes_key))

                    else:
                        break
            else:
                client_socket.sendall(aes_encrypt("Incorrect password.", aes_key))
        else:
            client_socket.sendall(aes_encrypt("Username not found.", aes_key))

    # Remove client from active clients on disconnect
    if username in clients:
        del clients[username]



def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 65432))
    server.listen(5)
    print("Server listening on port 65432...")

    while True:
        try:
            client_socket, addr = server.accept()
        except KeyboardInterrupt:
            print("Server interrupted. Shutting down gracefully.")
            server.close()
            break
        print(f"Connection from {addr}")
        client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_thread.start()


if __name__ == "__main__":
    main()
