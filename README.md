# Secure Chat System

## Overview
This is a CLI-based secure chat application that implements end-to-end encryption in python using Diffie-Hellman key exchange and AES encryption. The system provides secure user registration, login, and real-time messaging.

## Features
- Secure user registration and authentication
- End-to-end encryption using Diffie-Hellman key exchange
- AES encryption for message communication
- Threaded server to handle multiple client connections
- Secure credential storage

## Technologies Used
- Python
- Socket Programming
- Cryptography (PyCryptodome)
- JSON for data serialization
- Threading for concurrent client handling

## Security Mechanisms
- Diffie-Hellman key exchange for shared secret generation
- AES encryption in CBC mode
- Secure random number generation
- Salted password hashing

## Prerequisites
- Python 3.8+
- PyCryptodome library
- Socket library

## Installation
1. Clone the repository
2. Install required dependencies:
    ```bash
    pip install pycryptodome
    pip install pyinstaller  
    ```
3. Run the server:
    ```bash
    python server.py
    ```
4. Run the client:
    ```bash
    python client.py
    ```

## Usage
1. Register a new user
2. Login with registered credentials
3. Send and receive secure messages


## Security Notes
- Credentials are stored with salted hashes
- Messages are encrypted before transmission
- Uses a simple Diffie-Hellman key exchange (Note: For production, use more robust key exchange methods)

## Limitations
- Proof-of-concept implementation
- Uses small prime numbers for Diffie-Hellman (not suitable for production)
- No persistent message storage
