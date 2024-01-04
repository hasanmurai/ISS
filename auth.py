import sqlite3
import json
from Symmetric_Encryption import symmetric_encryption, symmetric_decryption, generate_symmetric_key


DATABASE_NAME = "ISS.db"

def create_database():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            phone_number TEXT,
            address TEXT,
            national_number TEXT,                       
            role TEXT,
            symmetric_key TEXT,
            public_key TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP

        )
    ''')


    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users_projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            project_name TEXT,
            project_info TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doctor_id INTEGER,
            name TEXT,     
            year TEXT,  
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (doctor_id) REFERENCES users(id) ON DELETE CASCADE
        
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS marks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_id INTEGER,
            student_name TEXT,
            student_mark TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE
        
        )
    ''')

    conn.commit()
    conn.close()


def create_account(client_socket, username,password):
    try:
                conn = sqlite3.connect(DATABASE_NAME)
                key=generate_symmetric_key()
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, password, symmetric_key)
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
          
            cursor.execute("SELECT symmetric_key FROM users WHERE username = ?", (username,))
            isKey= cursor.fetchone()
        if isKey:
                
            key= isKey[0]
            request= client_socket.recv(1024).decode()
            data=json.loads(request)
            
            decrypted_data= symmetric_decryption(data, key)
            print(decrypted_data)
            phone_number= decrypted_data.get("phone_number")
            address= decrypted_data.get("address")
            national_number= decrypted_data.get("national_number")
            role= decrypted_data.get("role")
                            
            cursor.execute('''
            UPDATE users SET phone_number = ?, address = ?, 
                national_number = ?, role = ? WHERE username = ?
            ''', (phone_number, address, national_number, role, username))
            conn.commit()
            response = {"message": "Information Updated", "role": role,"status":200}
            print(response)
            response = symmetric_encryption(response, key)
            print(f"{username} had completed his information")
            

            
    except sqlite3.Error as e:
            response = {"message":  f"Error during completing information: {str(e)} ","status":400}
            
    finally:  
        response = json.dumps(response, default=lambda x: str(x))
        client_socket.send(response.encode())
        conn.close()


def login(client_socket, username, password):
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT role, password FROM users WHERE username=?', (username,))
        account = cursor.fetchone()
        
        if account and password==account[1]:
            response = {"message": "Login successful", "role": account[0], "status":200} 
            print(f"{username} logged in")
       
        else:
            response = {"message": "Invalid username or password", "status" :404}
    except sqlite3.Error as e:
        response = {"message": f"Error during login: {str(e)}"}
    finally:

        response_json = json.dumps(response, default=lambda x: str(x))
        client_socket.send(response_json.encode())
        conn.close()

