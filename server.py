import socket
import json
import sqlite3
import threading
from Asymmetric_Encryption import *
from auth import *

from Symmetric_Encryption import symmetric_encryption, symmetric_decryption, hash_string
from datetime import datetime


def get_date():
    date = datetime.now()
    str_date = date.strftime("%d/%m/%Y %H:%M:%S")
    return str_date

############################################################################################################

def handshake_server(client_socket, username):
    try:

        request = client_socket.recv(8192).decode()
        data = json.loads(request)
        if data.get('action')=='handshake':
            client_certificate= data.get('certificate')
            client_certificate=x509.load_pem_x509_certificate(client_certificate.encode(), default_backend())    
            verify_client_cert=verify_certificate(client_certificate, server_certificate.public_key())
            
            username_from_certificate = client_certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            

            if verify_client_cert and username == username_from_certificate: 
                
                user_public_key_str= data.get("client_public_key")
                server_public_key_str=public_key_to_str(server_public_key)
                
                response = {'server_public_key':server_public_key_str,'status':200}  
                client_socket.send(json.dumps(response).encode())       
                session_key_recv(username, client_socket, user_public_key_str)
            else:
                response= {'message':'unvalid certificate','status':400}
        else:
             response={'message':'wrong action','status':400}
    except Exception as e:
        response={"message": f"An error occurred: {str(e)}", "status":400}
    finally :
        
        client_socket.send(json.dumps(response).encode())       
        



def session_key_recv(username, client_socket, user_public_key_str):
    try:

        request= client_socket.recv(10000).decode()
        data= json.loads(request)
        message= data.get("message")
        message= asymmetric_decryption(message.encode('latin-1'), server_private_key)

        if message == "True":
            session_key= data.get("session_key")
            session_key= asymmetric_decryption(session_key.encode('latin-1'), server_private_key)
            
            response= {"message":'accept, session started',"accept": 'true'}

            response= symmetric_encryption(response, session_key.encode())
            print(f'start session with {username}')
            
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username=? AND public_key is NULL', (username,))
            user_key=cursor.fetchone()
            
            if user_key:
                cursor.execute('UPDATE users SET public_key=? WHERE username=?', (user_public_key_str, username))
                conn.commit()
            user_public_key= str_to_public_key(user_public_key_str)
                

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
        main_menu(client_socket, username, session_key,user_public_key)

        
############################################################################################################
def add_projects(client_socket, data, username, session_key,user_public_key):
    try:

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT id, role FROM users WHERE username=? ', (username,))
        user_role=cursor.fetchone()
        encrypted_projects = data.get('projects')
        if user_role[1]=='1':
            encrypted_projects = [(project[0], project[1]) for project in encrypted_projects]
            projects= symmetric_decryption(encrypted_projects, session_key)

            projects_names=[]
            for item in projects:
                cursor.execute('INSERT INTO users_projects (user_id, project_name, project_info) VALUES (?, ?, ?)',
                        (user_role[0], item[0], item[1]))
                conn.commit()
                projects_names.append(item[0])
            
            response= {'message':f'{username} added projects {projects_names} successfully', 'status':200}
            
            response= symmetric_encryption(response,session_key)
            print(f'{username} added projects {projects_names}')
        else:
            response= {'message':'user not allowed','status':400}
            

    except sqlite3.Error as e:
            
            response = {"message": f"Error creating account: {str(e)}", 'status':400}
    except socket.error as e:
            response = {"message": f"Error creating : {str(e)}", 'status':400}

    finally:
        conn.close()
        client_socket.send(json.dumps(response).encode())  
        main_menu(client_socket, username,session_key,user_public_key)

def add_marks(client_socket,username,data,session_key,user_public_key):
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT id, role FROM users WHERE username=? ', (username,))
        doctor=cursor.fetchone()
        
        if doctor and doctor[1]=='2':
            subject_name= symmetric_decryption(data.get('subject_name'),session_key)
            year= symmetric_decryption(data.get('year'),session_key)
            students_names= symmetric_decryption(data.get('students_names'),session_key)
            students_marks= symmetric_decryption(data.get('students_marks'),session_key)
    
            hashed_data= data.get('data')
            
            signature= data.get('signature').encode('latin-1')

            merge_all_data= ' '.join([subject_name+year]+students_names+students_marks)
            
            hash_data= hash_string(merge_all_data)
            
            verify_sign= verify_signature(hash_data, signature, user_public_key)

            if hash_data==hashed_data:
                if verify_sign:

                    cursor.execute('''INSERT INTO subjects (doctor_id, name, year) 
                                VALUES (?,?,?)''',(doctor[0],subject_name, year))
                    cursor.execute("SELECT id FROM subjects WHERE name=? AND year=?",(subject_name,year))
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
        main_menu(client_socket, username, session_key,user_public_key)


def show_marks(client_socket,username,data, session_key,user_public_key):
    try:
        user=data.get('username')
        print(user)
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
        SELECT marks.student_name, marks.student_mark, subjects.name, subjects.year
        FROM marks
        JOIN subjects ON marks.subject_id = subjects.id
        WHERE marks.student_name = ?
    ''', (user,))

        results = cursor.fetchall()
        subject_mark_list = [(result[2], result[3], result[1]) for result in results]
        subject_mark_list=symmetric_encryption(subject_mark_list, session_key)

        response={'list':subject_mark_list,'status':200}
        print(112233)
    except sqlite3.Error as e:
            response = {"message":f"Error creating : {str(e)}", 'status':400}
    except socket.error as e:
            response = {"message": f"Error creating : {str(e)}", 'status':400}
    except Exception as e:
            response = {"message": f"Error creating : {str(e)}", 'status':400}
    finally:
        conn.close()
        client_socket.sendall(json.dumps(response).encode())
        print(response)
        main_menu(client_socket, username, session_key,user_public_key)   


def main_menu(client_socket, username, session_key,user_public_key):
    while True:
        request= client_socket.recv(50000).decode()
        data= json.loads(request)
        action= data.get('action')
        print(f'{username} want to {action}')
        if action == 'send_project':
            
            add_projects(client_socket,data , username, session_key,user_public_key)
        elif action == 'send_marks':
            add_marks(client_socket,username,data,session_key,user_public_key) 
        elif action == 'show_marks':
            show_marks(client_socket,username,data,session_key,user_public_key)
        else:
            response = {"message": "Invalid action",'status':400}
            client_socket.send(json.dumps(response).encode("utf-8"))    

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
    server_socket.listen()

    create_database()
    global server_public_key, server_private_key
    server_private_key= generate_rsa_keys()
    server_public_key= server_private_key.public_key()
    server_csr= generate_csr(server_private_key, 'Main Server')
    
    ca_socket= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ca_socket.connect(('127.0.0.1', 5001))
    response= {'sender':'server', 'csr':server_csr.public_bytes(Encoding.PEM).decode()}
    ca_socket.send(json.dumps(response).encode())
    
    request= ca_socket.recv(4096).decode()
    data= json.loads(request)
    
    global server_certificate
    server_certificate= data.get('signed_certificate')
    server_certificate=x509.load_pem_x509_certificate(server_certificate.encode(), default_backend())
    print("Server listening on port 5000")
    
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
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

    
