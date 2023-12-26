import socket
import json
import sqlite3
import threading
import gnupg
from auth import create_database, create_account, login, complete_information
from pgp import generate_pgp_keys, pgp_encryption, pgp_decryption

server_name = "FITE"
server_email="fitedamascus@gmail.com"
server_passphrase="Damascus Univercity"
############################################################################################################

# def generate_symmetric_key():
#     key=Fernet.generate_key()
#     return key

# def symmetric_encryption(data, key):
#     fernet = Fernet(key)
#     encrypted_data = {}

#     for field, value in data.items():
#         encrypted_data[field] = fernet.encrypt(value.encode()).decode()

#     return encrypted_data

# def symmetric_decryption(encrypted_data, key):
#     fernet = Fernet(key)
#     decrypted_data = {}

#     for field, value in encrypted_data.items():
#         decrypted_data[field] = fernet.decrypt(value)  
        
#     return decrypted_data

############################################################################################################

# def create_keys():
DATABASE_NAME="ISS.db"
def handshake_server(client_socket, server_public_key):
    try:
        request = client_socket.recv(2048).decode()
        data = json.loads(request)
        user_public_key= data.get("client_public_key")
        response = {'message':True, 'server_public_key':server_public_key}
    except Exception as e:
        response={"message": f"An error occurred: {str(e)}", "status":400}
    finally :
        client_socket.send(json.dumps(response).encode())   


############################################################################################################


def handle_client(client_socket, server_public_key, server_private_key):
    create_database()
    data = client_socket.recv(1024).decode("utf-8")
    request = json.loads(data)
    action = request.get("action")
    username = request.get("username")
    password = request.get("password")

    if action == "create_account":
        create_account(client_socket, username, password)
    # if action == "complete_information":
        complete_information(client_socket, username)
        handshake_server(client_socket, server_public_key)
    elif action == "login":
        login(client_socket, username, password)
        
    else:
        response = {"message": "Invalid action"}
        client_socket.send(json.dumps(response).encode("utf-8"))
        client_socket.close()

    

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 5000))
    server_socket.listen(5)

    print("Server listening on port 5000")
    
    gpg = gnupg.GPG()
    
    server_keys = generate_pgp_keys(gpg, server_name, server_email, server_passphrase)
    server_public_key = gpg.export_keys(server_keys.fingerprint)
    server_private_key  = gpg.export_keys(server_keys.fingerprint, secret=True,
                                                                  passphrase=server_passphrase)

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")

        # Create a new thread for each client
        client_thread = threading.Thread(target=handle_client, args=(client_socket, server_public_key, server_private_key))
        client_thread.start()

if __name__ == "__main__":
    start_server()
