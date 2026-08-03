import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


# Generate Server RSA Key Pair

server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

server_public_key = server_private_key.public_key()

# Serialize Public Key
server_public_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Serialize Private Key 
server_private_bytes = server_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)


# Socket Setup

HOST = "127.0.0.1"
PORT = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#Bind IP and Port
server_socket.bind((HOST, PORT))  
#Listen for incoming connection requests
server_socket.listen(1)           

print("SERVER STARTED")
print(f"Listening on {HOST}:{PORT}")

#Accept a connection
client_socket, addr = server_socket.accept()  

print(f"\nConnected to {addr}")

# Exchange Public Keys

# Send server public key
client_socket.sendall(server_public_bytes)

# Receive client public key
client_public_bytes = client_socket.recv(2048)

# Convert the received public key bytes into an RSA public key object
client_public_key = serialization.load_pem_public_key(
    client_public_bytes
)

print("\nClient Public Key Received Successfully.\n")

running = True


def receive_loop():

    #Continuously listen for and decrypt messages from the client
    global running
    while running:
        try:
            encrypted_msg = client_socket.recv(2048)
        except OSError:
            break

        if not encrypted_msg:
            running = False
            break

        print("\n==============================================")
        print("RECEIVER (SERVER)")
        print("==============================================")

        print("\nReceiver's Private Key:\n")
        print(server_private_bytes.decode())

        print("Encrypted Text (HEX):\n")
        print(encrypted_msg.hex())

        # Decrypt
        decrypted_msg = server_private_key.decrypt(
            encrypted_msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

        print("\nDecrypted Text:")
        print(decrypted_msg)

        print("==============================================")

        if decrypted_msg.lower() == "bye":
            print("\nClient ended the chat.")
            running = False
            break

    
        print("\nEnter message: ", end="", flush=True)


def send_loop():
    #Continuously read operator input, encrypt it, and send it to the client
    global running
    while running:
        try:
            reply = input("\nEnter message: ")
        except (EOFError, KeyboardInterrupt):
            running = False
            break

        print("\n==============================================")
        print("SENDER (SERVER)")
        print("==============================================")

        print("\nReceiver's Public Key:\n")
        print(client_public_bytes.decode())

        print("Plain Text:")
        print(reply)

        encrypted_reply = client_public_key.encrypt(
            reply.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print("\nEncrypted Text (HEX):")
        print(encrypted_reply.hex())

        print("==============================================")

        try:
            client_socket.sendall(encrypted_reply)
        except OSError:
            running = False
            break

        if reply.lower() == "bye":
            print("\nServer ended the chat.")
            running = False
            break


# Start receiving in the background so it never blocks sending
receiver = threading.Thread(target=receive_loop, daemon=True)
receiver.start()

send_loop()

client_socket.close()
server_socket.close()

print("\nConnection Closed.")