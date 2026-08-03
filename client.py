import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# =====================================================
# Generate Client RSA Key Pair
# =====================================================
client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

client_public_key = client_private_key.public_key()

# Serialize Public Key
client_public_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Serialize Private Key (Only for demonstration)
client_private_bytes = client_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# =====================================================
# Socket Setup
# =====================================================
HOST = "127.0.0.1"
PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

print("======================================")
print("CLIENT CONNECTED")
print("======================================")

# =====================================================
# Exchange Public Keys
# =====================================================

# Receive server's public key
server_public_bytes = client_socket.recv(2048)

server_public_key = serialization.load_pem_public_key(
    server_public_bytes
)

# Send client's public key
client_socket.sendall(client_public_bytes)

print("\nServer Public Key Received Successfully.\n")

# =====================================================
# Chat Loop (threaded so send/receive don't block each other)
# =====================================================

running = True


def receive_loop():
    """Continuously listen for and decrypt replies from the server."""
    global running
    while running:
        try:
            encrypted_reply = client_socket.recv(2048)
        except OSError:
            break

        if not encrypted_reply:
            running = False
            break

        print("\n==============================================")
        print("RECEIVER (CLIENT)")
        print("==============================================")

        print("\nReceiver's Private Key:\n")
        print(client_private_bytes.decode())

        print("Encrypted Text (HEX):\n")
        print(encrypted_reply.hex())

        # Decrypt reply
        decrypted_reply = client_private_key.decrypt(
            encrypted_reply,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

        print("\nDecrypted Text:")
        print(decrypted_reply)

        print("==============================================")

        if decrypted_reply.lower() == "bye":
            print("\nServer ended the chat.")
            running = False
            break

        # Re-show the prompt since send_loop's input() call is already
        # blocked waiting and won't print it again on its own.
        print("\nEnter message: ", end="", flush=True)


def send_loop():
    """Continuously read user input, encrypt it, and send it to the server."""
    global running
    while running:
        try:
            message = input("\nEnter message: ")
        except (EOFError, KeyboardInterrupt):
            running = False
            break

        print("\n==============================================")
        print("SENDER (CLIENT)")
        print("==============================================")

        print("\nReceiver's Public Key:\n")
        print(server_public_bytes.decode())

        print("Plain Text:")
        print(message)

        encrypted_msg = server_public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print("\nEncrypted Text (HEX):")
        print(encrypted_msg.hex())

        print("==============================================")

        try:
            client_socket.sendall(encrypted_msg)
        except OSError:
            running = False
            break

        if message.lower() == "bye":
            print("\nClient ended the chat.")
            running = False
            break


# Start receiving in the background so it never blocks sending
receiver = threading.Thread(target=receive_loop, daemon=True)
receiver.start()

send_loop()

client_socket.close()

print("\nConnection Closed.")