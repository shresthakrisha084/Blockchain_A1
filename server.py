import socket
from main import *

def generate_keys():
    private_key = RSA.generate(1024)
    public_key = private_key.publickey()

    return private_key, public_key
    
def socket_server():
    # Generate new random key for the session
    session_key = get_session_key()

    # Get the hostname
    host = socket.gethostname()
    port = 8085

    # Get socket instance
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.bind((host, port))

    # Server listen configuration
    server.listen(1) 
    server, address = server.accept()
    print(f"Client {address} connected ...")

    # Get Client's public key
    client_public_key = RSA.import_key(server.recv(1024))
    
    # Encrypt Session Key
    enc_session_key = encrypt_session_key(client_public_key, session_key)
    server.send(bytes(enc_session_key))

    while True:
        data =server.recv(1024)
        if not data:
            break
        
        print("Client's Encrypted Message: ", str(data))
        plain_text = decrypt_AES(session_key, data)

        print("Client's Decrypted Message: " + str(plain_text))
        print("-"*35)
        message = bytes(input('enter a reply: '), "utf-8")

        if message.lower().strip() ==b'quit':
            break
        
        ciphertext = encrypt_AES(session_key, message)
        server.send(ciphertext)

    server.close()

if __name__ == "__main__":
    socket_server()