import socket
import hashlib
import json
import secrets
from Crypto.Cipher import AES
import threading
from Crypto.Util.Padding import pad, unpad

# Constants for Diffie-Hellman
P = 23  # Prime number
G = 5   # Generator


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


def client_register(client_socket, aes_key):
    email = input("Email: ")
    username = input("Username: ")
    password = input("Password: ")
    registration_data = json.dumps({"username": username, "email": email, "password": password})
    client_socket.sendall(aes_encrypt("register", aes_key))
    client_socket.sendall(aes_encrypt(registration_data, aes_key))


def client_login(client_socket, aes_key):
    username = input("Username: ")
    password = input("Password: ")
    login_data = json.dumps({"username": username, "password": password})
    client_socket.sendall(aes_encrypt("login", aes_key))
    client_socket.sendall(aes_encrypt(login_data, aes_key))


def receive_message(client_socket, aes_key):
    data = b""
    while True:
        chunk = client_socket.recv(1024)
        if not chunk:
            print(f"Connection lost.")
            break
        # print(f"Received chunk: {chunk}")
        data += chunk
        if len(data) > 0:
            break
    message = aes_decrypt(data, aes_key)
    return message



def receive_messages(client_socket, aes_key):
    # print("Started receiving messages.")
    while True:
        message = receive_message(client_socket, aes_key)
        if message:
            print(f"\n{message}")
            pass
        else:
            print("No new message received.")


def client_chat(client_socket, aes_key):
    threading.Thread(target=receive_messages, args=(client_socket, aes_key), daemon=True).start()
    print("Enter 'bye' to exit chat.")
    
    while True:
        recipient = input("Send to (username): ")
        message = input("You: ")
        if message.lower() == "bye":
            break
        data = json.dumps({"recipient": recipient, "message": message})
        print(f"Sending message to {recipient}: {message}")  # Debug output
        client_socket.sendall(aes_encrypt(data, aes_key))




def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 65432))

    # Diffie-Hellman key exchange
    client_private_key, client_public_key = diffie_hellman_generate_key()
    client_socket.sendall(str(client_public_key).encode())
    server_public_key = int(client_socket.recv(1024).decode())
    shared_secret = diffie_hellman_compute_shared_key(client_private_key, server_public_key)
    aes_key = hashlib.sha256(str(shared_secret).encode()).digest()[:16]  # AES-128 key

    action = input("Choose an action (register or login):  ")
    if action == "register":
        client_register(client_socket, aes_key)
    elif action == "login":
        client_login(client_socket, aes_key)
        response = aes_decrypt(client_socket.recv(1024), aes_key)
        print(response)
        if "successful" in response:
            client_chat(client_socket, aes_key)
    client_socket.close()


if __name__ == "__main__":
    main()
