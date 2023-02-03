import socket
from main import *

def generate_keys():
    private_key = RSA.generate(1024)
    public_key = private_key.publickey()

    return private_key, public_key

def socket_client():
    host = socket.gethostname() 
    port = 8085

    private_key, public_key = generate_keys()

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    client_socket.send(public_key.export_key())

    enc_session_key = client_socket.recv(1024)
    session_key = decrypt_session_key(private_key, enc_session_key)
    
    message = bytes(input("enter a message: "), "utf-8")

    while message.lower().strip() != b'quit':
        ciphertext = encrypt_AES(session_key, message)
        print("Encrypted Message: ",ciphertext)

        client_socket.send(ciphertext)


        response = client_socket.recv(1024)
        if not response:
            break

        print('Server Encrypred Reply: ' + str(response))

        plain_response = decrypt_AES(session_key, response)

        print('Server Decrypred Reply: ' + str(plain_response))
        print("-"*35)
        message = bytes(input("Enter a message: "), "utf-8")
    client_socket.close() 


if __name__ == '__main__':
    socket_client()