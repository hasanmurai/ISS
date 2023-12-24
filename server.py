import socket
import json
import sqlite3
import threading
from cryptography.fernet import Fernet


DATABASE_NAME = "accounts.db"

def create_table():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            phone_number TEXT,
            address TEXT,
            national_number TEXT,                       
            role TEXT,
            key TEXT

        )
    ''')

    conn.commit()
    conn.close()


def encryption_key():
    key=Fernet.generate_key()
    return key

def symmetric_encryption(data, key):
    fernet = Fernet(key)
    encrypted_data = {}

    for field, value in data.items():
        encrypted_data[field] = fernet.encrypt(value.encode()).decode()

    return encrypted_data


def symmetric_decryption(encrypted_data, key):
    fernet = Fernet(key)
    decrypted_data = {}

    for field, value in encrypted_data.items():
        decrypted_data[field] = fernet.decrypt(value)  
        
    return decrypted_data


def account_exists(username):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM accounts WHERE username=?", (username,))
    account = cursor.fetchone()
    conn.close()

    return account is not None

def create_account(client_socket, username,password):
    try:
            conn = sqlite3.connect(DATABASE_NAME)

            if account_exists(username):
                response = {"message": "Username already exists","encryption_key":False}
            else:
                key=encryption_key()
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO accounts (username, password, key)
                    VALUES (?, ?, ?)
                ''', (username, password, key))
                conn.commit()
                response = {"message": "Account created successfully","encryption_key": key.decode()}
    except sqlite3.Error as e:
            response = {"message": f"Error creating account: {str(e)}"}
    finally:
        conn.close()
        response_json = json.dumps(response, default=lambda x: str(x))
        client_socket.send(response_json.encode())
        

def complete_information(client_socket, username):
        try:
        
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
        # cursor.execute('SELECT * FROM accounts WHERE username=? AND address IS NULL', (username,))
        # information = cursor.fetchone()

        # if information:
          
            cursor.execute("SELECT key FROM accounts WHERE username = ?", (username,))
            isKey= cursor.fetchone()
        # if isKey:
                
            key= isKey[0]
            request= client_socket.recv(1024).decode()
            data=json.loads(request)
            
            decrypted_data= symmetric_decryption(data, key)
            phone_number= decrypted_data.get("phone_number")
            address= decrypted_data.get("address")
            national_number= decrypted_data.get("national_number")
            role= decrypted_data.get("role")
                            
            cursor.execute('''
            UPDATE accounts SET phone_number = ?, address = ?, 
                national_number = ?, role = ? WHERE username = ?
            ''', (phone_number, address, national_number, role, username))
            conn.commit()
            response = {"message": "Information Updated", "role": role.decode()}
            response = symmetric_encryption(response, key)

            
    # except sqlite3.Error as e:
    #         response = {"message":  f"Error during completing information: {str(e)}"}
        finally:
            response_json = json.dumps(response, default=lambda x: str(x))
            client_socket.send(response_json.encode())
            conn.close()


def login(client_socket, username, password):
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM accounts WHERE username=? AND password=?', (username, password))
        account = cursor.fetchone()

        if account:
            response = {"message": "Login successful", "role": '1', "status":200}        
        else:
            response = {"message": "Invalid username or password", "status" :404}
    except sqlite3.Error as e:
        response = {"message": f"Error during login: {str(e)}"}
    finally:
        conn.close()
        response_json = json.dumps(response, default=lambda x: str(x))
        client_socket.send(response_json.encode())
        conn.close()


def handle_client(_client_socket_):
    create_table()
    client_socket= _client_socket_
    data = client_socket.recv(1024).decode("utf-8")
    request = json.loads(data)
    action = request.get("action")
    username = request.get("username")
    password = request.get("password")

    if action == "create_account":
        create_account(client_socket, username, password)
        complete_information(client_socket, username)
        

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

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")

        # Create a new thread for each client
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

if __name__ == "__main__":
    start_server()
