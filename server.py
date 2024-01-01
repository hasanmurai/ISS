import base64
import socket
import json
import sqlite3
import threading
import tkinter as tk

import rsa
from auth import create_database, create_account, login, complete_information
from _rsa_ import generate_rsa_keys, rsa_encrypt, rsa_decrypt , rsa_verify_signature
from symmetric_key import symmetric_encryption, symmetric_decryption, hash_string
from datetime import datetime


def get_date():
    date = datetime.now()
    str_date = date.strftime("%d/%m/%Y %H:%M:%S")
    return str_date

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
def handshake_server(client_socket, username):
    try:
        disconnet=True
        request = client_socket.recv(2048).decode()
        data = json.loads(request)
        disconnet=False
        if data.get('action')=='close':
            print(f"{data.get('username')} disconnet!")
            client_socket.close()
        else:     
            user_public_key_str= data.get("client_public_key")
            
            server_public_key_str=server_public_key.save_pkcs1().decode()
            
            response = {'message':True, 'server_public_key':server_public_key_str}  
            client_socket.send(json.dumps(response).encode())       
            session_key_recv(username,client_socket,server_private_key, user_public_key_str)


    except Exception as e:
        response={"message": f"An error occurred: {str(e)}", "status":400}
    finally :
        if disconnet:
            client_socket.send(json.dumps(response).encode())       
        else:
            pass



def session_key_recv(username,client_socket, server_private_key, user_public_key_str):
    try:

        request= client_socket.recv(2048).decode()

        data= json.loads(request)

        if data.get("message"):
            decrypt_session_key= data.get("session_key")
            session_key= rsa_decrypt(base64.b64decode(decrypt_session_key), server_private_key)
            
            response= {"message":'accept, session started',"status": 200}
            response= symmetric_encryption(response, session_key.encode())
            print(f'start session with {username}')
            
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username=? AND public_key is NULL', (username,))
            user_key=cursor.fetchone()
            
            if user_key:
                cursor.execute('UPDATE users SET public_key=? WHERE username=?', (user_public_key_str, username))
                conn.commit()
                

        else:
            response = {"message":  "Error fdf completing information: ","status":400}
        
    except socket.error as e:
         response = {"message":  "Error fdf completing information: ","status":400}
    except sqlite3.Error as e:
            response = {"message":  f"Error during completing information: {str(e)} ","status":400}
           
    except Exception as e:
        response={"message": f"An error occurred: {str(e)}", "status":400}
    finally:
        if conn:
            conn.close()
        client_socket.send(json.dumps(response).encode())
        main_menu(client_socket, username, session_key,user_public_key_str)

        
############################################################################################################
def add_projects(client_socket, encrypted_projects, username, session_key,user_public_key_str):
    try:

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT id, role FROM users WHERE username=? ', (username,))
        user_role=cursor.fetchone()
         
        if user_role[1]=='1':
            projects= symmetric_decryption(encrypted_projects, session_key)
            projects_names=[]
            for item in projects:
                cursor.execute('INSERT INTO users_projects (user_id, project_name, project_info) VALUES (?, ?, ?)',
                        (user_role[0], item[0], item[1]))
                conn.commit()
                projects_names.append(item[0])
            response= {'message':f'{username} add projects {projects_names} successfully', 'status':200}
            
            response= symmetric_encryption(response,session_key)
        else:
            response= {'message':'user not allowed','status':400}
            

    except sqlite3.Error as e:
            
            response = {"message": f"Error creating account: {str(e)}", 'status':400}
    except socket.error as e:
            response = {"message": f"Error creating : {str(e)}", 'status':400}

    finally:
        conn.close()
        client_socket.send(json.dumps(response).encode())  
        main_menu(client_socket, username,session_key,user_public_key_str)

def add_marks(client_socket,username,data,session_key,user_public_key_str):
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT id, role FROM users WHERE username=? ', (username,))
        doctor=cursor.fetchone()
        
        if doctor and doctor[1]=='2':
            subject_name= symmetric_decryption(data.get('subject_name'),session_key)
            students_names= symmetric_decryption(data.get('students_names'),session_key)
            students_marks= symmetric_decryption(data.get('students_marks'),session_key)
    
            hashed_data= data.get('data')
            
            signature= data.get('signature').encode('latin-1')
           
            # signature= base64.b64encode(signature).decode()
            
            
            merge_all_data= ' '.join([subject_name]+students_names+students_marks)
            
            hash_data= hash_string(merge_all_data)
            user_public_key=rsa.PublicKey.load_pkcs1(user_public_key_str.encode())
            verify_sign= rsa_verify_signature(hash_data,signature,user_public_key)

            if hash_data==hashed_data:
                if verify_sign:

                    cursor.execute('''INSERT INTO subjects (doctor_id, name) 
                                VALUES (?,?)''',(doctor[0],subject_name))
                    cursor.execute("SELECT id FROM subjects WHERE name=?",(subject_name,))
                    subject_id=cursor.fetchone()
                    if subject_id:
                        for data in zip([subject_id[0]] * len(students_names), students_names, students_marks):
                            cursor.execute('''INSERT INTO marks (subject_id, student_name, student_mark) 
                                            VALUES (?,?,?)''',(data))    
                        conn.commit()
                        response= {'message':'marks added successfully','status':200}
                        response= symmetric_encryption(response,session_key)
                        print(f'{username} added {subject_name}')
                    
                    else:
                        response= {'message':'subject not found','status':400}          
                else:
                    response={'message':'wrong signature','status':400}    
            else:
                response:{'message':'data been changed','status':400}                                         
        else:
            response= {'message':'user not allowed','status':400} 
        
    except sqlite3.Error as e:
            response = {"message":f"Error creating : {str(e)}", 'status':400}
    except socket.error as e:
            response = {"message": f"Error creating : {str(e)}", 'status':400}

    finally:
        conn.close()
        client_socket.send(json.dumps(response).encode())
        main_menu(client_socket, username, session_key,user_public_key_str)


def main_menu(client_socket, username, session_key,user_public_key_str):
    while True:
        request= client_socket.recv(50000).decode()
        data= json.loads(request)
        action= data.get('action')
        print(f'{action} {username}')
        if action == 'send_project':
            encrypted_projects = data.get('projects')
            add_projects(client_socket,encrypted_projects, username, session_key,user_public_key_str)
        elif action == 'send_marks':
            add_marks(client_socket,username,data,session_key,user_public_key_str) 


def handle_client(client_socket):
    
        data = client_socket.recv(10000).decode("utf-8")

        request = json.loads(data)
        action = request.get("action")
    
        if action == "create_account":

            username = request.get("username")
            password = request.get("password")
            create_account(client_socket, username, password)
            complete_information(client_socket, username)
            handshake_server(client_socket, username)
            
        elif action == "login":

            username = request.get("username")
            password = request.get("password")        
            login(client_socket, username, password)
            handshake_server(client_socket, username)
    
        else:
            
            response = {"message": "Invalid action",'status':400}
            client_socket.send(json.dumps(response).encode("utf-8"))
            client_socket.close()

    

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 5000))
    server_socket.listen(5)

    create_database()
    global server_public_key, server_private_key
    server_public_key, server_private_key= generate_rsa_keys()
    
    print("Server listening on port 5000")
    
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")

        # Create a new thread for each client
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

# root = tk.Tk()

# root.title("SERVER")
# x = root.winfo_screenwidth() // 3
# y = int(root.winfo_screenheight() * 0.2)
# root.geometry('500x400+' + str(x) + '+' + str(y))
# root.grid_rowconfigure(0, weight=1)
# root.grid_rowconfigure(1, weight=0)
# root.grid_columnconfigure(0, weight=1)

# response_frame=tk.Frame(root)
# response_frame.grid(row=0, column=0, sticky="nesw")
# server_listbox = tk.Listbox(response_frame, selectmode=tk.SINGLE, width=50, height=23)
# server_listbox.pack(pady=10)

if __name__ == "__main__":
    start_server()

    
