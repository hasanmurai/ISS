import sqlite3
import json
from symmetric_key import symmetric_encryption, symmetric_decryption, generate_symmetric_key


DATABASE_NAME = "ISS.db"

def create_database():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            public_key TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        
        )
    ''')


    conn.commit()
    conn.close()

def account_exists(username):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    account = cursor.fetchone()
    conn.close()

    return account is not None

def create_account(client_socket, username,password):
    try:
            conn = sqlite3.connect(DATABASE_NAME)

            if account_exists(username):
                response = {"message": "Username already exists","encryption_key":False}
            else:
                key=generate_symmetric_key()
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, password, key)
                    VALUES (?, ?, ?)
                ''', (username, password, key))
                conn.commit()
                response = {"message": "Account created successfully","encryption_key": key.decode()}
                print(f"{username} had created an account")

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
        cursor.execute('SELECT * FROM users WHERE username=? AND address IS NULL', (username,))
        information = cursor.fetchone()

        if information:
          
            cursor.execute("SELECT key FROM users WHERE username = ?", (username,))
            isKey= cursor.fetchone()
        if isKey:
                
            key= isKey[0]
            request= client_socket.recv(1024).decode()
            data=json.loads(request)
            
            decrypted_data= symmetric_decryption(data, key)
            phone_number= decrypted_data.get("phone_number")
            address= decrypted_data.get("address")
            national_number= decrypted_data.get("national_number")
            role= decrypted_data.get("role")
                            
            cursor.execute('''
            UPDATE users SET phone_number = ?, address = ?, 
                national_number = ?, role = ? WHERE username = ?
            ''', (phone_number, address, national_number, role, username))
            conn.commit()
            response = {"message": "Information Updated", "role": role.decode(),"status":'200'}
            response = symmetric_encryption(response, key)
            print(f"{username} had completed his information")
            response = json.dumps(response, default=lambda x: str(x))

            
    except sqlite3.Error as e:
            response = {"message":  f"Error during completing information: {str(e)} ","status":400}
            
    finally:
            
        client_socket.send(response.encode())
        conn.close()


def login(client_socket, username, password):
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
        account = cursor.fetchone()

        if account:
            response = {"message": "Login successful", "role": '1', "status":200} 
            print(f"{username} logged in")
       
        else:
            response = {"message": "Invalid username or password", "status" :404}
    except sqlite3.Error as e:
        response = {"message": f"Error during login: {str(e)}"}
    finally:
        conn.close()
        response_json = json.dumps(response, default=lambda x: str(x))
        client_socket.send(response_json.encode())
        conn.close()

