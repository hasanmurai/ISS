import base64
import hashlib
import socket
import json
import pandas as pd
import tkinter as tk
from tkinter import W, Radiobutton, messagebox
from tkinter import filedialog

import rsa
from symmetric_key import generate_symmetric_key, symmetric_encryption, symmetric_decryption,hash_string
# from _rsa_ import generate_rsa_keys, save_keys_to_file, load_public_key, load_private_key, rsa_encrypt, rsa_decrypt,rsa_signature 
from asymmetric import *

def copy_to_clipboard(message,dialog):
    root.clipboard_clear()
    root.clipboard_append(message)
    root.update()
    dialog.destroy()



def create_account(entry_ip, entry_port, entry_username, entry_password):
    try:
        server_ip = entry_ip.get()
        server_port = int(entry_port.get())
        username = entry_username.get()
        password = hash_string(entry_password.get())

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, server_port))

        action = "create_account"
        request_data = {"action": action, "username": username, "password": password}
  
        client_socket.send(json.dumps(request_data).encode())
        response_data = client_socket.recv(1024)
        response = json.loads(response_data)

        messagebox.showinfo("Server Response", response['message'])

        # Display the encryption key in a custom dialog
        if response['encryption_key']:
            show_encryption_key(response['encryption_key'])
            Complete_Information_Frame(client_socket, username)
            
    except socket.error as e:
        messagebox.showerror("Connection Error", e)
        client_socket.close()
        root.destroy()
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")
    # finally:
    #     client_socket.close()




def login(entry_ip, entry_port, entry_username, entry_password):
    try:
        server_ip = entry_ip.get()
        server_port = int(entry_port.get())
        username = entry_username.get()
        password = hash_string(entry_password.get())

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, server_port))

        action = "login"
        request_data = {"action": action, "username": username, "password": password}
        client_socket.send(json.dumps(request_data).encode())

        response_data = client_socket.recv(1024).decode()
        response = json.loads(response_data)
        
        messagebox.showinfo("Server Response", response['message'])
        if response["status"]==200:
            role= response['role']
            print(role)
            Load_Client_Keys_Frame(client_socket,role,username)            
            
        else:
            client_socket.close()

    except socket.error as e:
        messagebox.showerror("Connection Error", e)
        client_socket.close()
        root.destroy()
    except Exception as e:
        messagebox.showerror("Error", f"An sderror occurred: {e}")

    # finally:
    #     client_socket.close()


def complete_information(username, client_socket, entry_phone_number,
                         entry_national_number, entry_address, entry_role, entry_key):
    try:
        
        action = "complete_info"
        
        phone_number = entry_phone_number.get()
        national_number = entry_national_number.get()
        address = entry_address.get()
        role = entry_role.get()
        key = entry_key.get()
        request_data = {"action": action, "phone_number": phone_number, "national_number": national_number,
                        "address": address, "role": role}
   
        encrypted_data = symmetric_encryption(request_data, key.encode())
      

        # client_socket.send(json.dumps(encrypted_data).encode())
        # response_json = json.dumps(encrypted_data, default=lambda x: str(x))
        client_socket.send(json.dumps(encrypted_data).encode())

        response_data = client_socket.recv(1024).decode()
        response = json.loads(response_data)
        response = symmetric_decryption(response,key)
        if response.get('status')== 400:
            messagebox.showerror("Error", f"An error has occurred:ss")
            client_socket.close()
            root.destroy()
        else:
            
            messagebox.showinfo("Server Response", response['message'])
            
            Create_Client_Keys_Frame(username, client_socket,role)

            # Student_or_Professor(response["role"], "complete_information_frame")
            
    except socket.error as e:
        messagebox.showerror("Connection Error", e)
    except Exception as e:
        messagebox.showerror("Error", f"An error has occurred: {e}")

    # finally:
    #     client_socket.close()
def generate_user_keys(client_socket,role,client_private_key_path):
    
    try:

        client_private_key= generate_rsa_keys() 

        save_private_key_to_file(client_private_key, client_private_key_path)
        
        handshake_client(client_socket,create_client_keys_frame,role,client_private_key_path)

    except Exception as e:
        messagebox.showerror("Error", f"An error has occurred: {e}")
        client_socket.close()
        root.destroy()


def handshake_client(client_socket,frame,role,client_private_key_path):
    try:

        client_private_key= load_private_key_from_file(client_private_key_path)
        if client_private_key:

            client_public_key= client_private_key.public_key()
            client_public_key_str= public_key_to_str(client_public_key)

            response = {"client_public_key": client_public_key_str}
            client_socket.send(json.dumps(response).encode())

            request= client_socket.recv(1024).decode()

            data= json.loads(request)
            
            if data['message']==True:
            
                server_public_key_str= data.get("server_public_key")
                server_public_key= str_to_public_key(server_public_key_str)
                
                create_session_key(client_socket, server_public_key, client_private_key, frame,role)
            
            else:    
                messagebox.showerror("Error",data.get('message'))
        else:
            messagebox.showerror('Error', 'path not found')        
    except socket.error as e:
        messagebox.showerror("Connection Error", "No dd available")
    except Exception as e:
        messagebox.showerror("Error", f"An error has occurred: {e}")
        # client_socket.close()
        # root.destroy()

def create_session_key(client_socket, server_public_key, client_private_key, frame,role):
    try:

        session_key= generate_symmetric_key()
        encrypted_session_key= asymmetric_encryption(session_key.decode(), server_public_key).decode('latin-1')
        message= asymmetric_encryption('True', server_public_key).decode('latin-1')

        request= {'message': message, "session_key": encrypted_session_key} #base64.b64encode(encrypt_session_key).decode()
        
        client_socket.send(json.dumps(request).encode())

        response= client_socket.recv(2048).decode()     
        response=json.loads(response)

        data=symmetric_decryption(response, session_key)  
        print('dd')

        if data.get('status')==200:
            messagebox.showinfo("Server Response", data.get('message'))
            Student_or_Professor(frame,role,client_socket,session_key,client_private_key)
    
    except Exception as e:
        messagebox.showerror("Erddror", f"An error has occurred: {e}")

        # client_socket.close()
        # root.destroy()

def send_project(projects,role,client_socket,session_key):
    try:
        action='send_project'
        encrypted_projects= symmetric_encryption(projects, session_key)
        request= {'action':action, 'projects':encrypted_projects}
        client_socket.send(json.dumps(request).encode())
        response= client_socket.recv(8192).decode()
        data= json.loads(response)
        
        status= data.get('status')
        if status == 200:
            data=symmetric_decryption(data,session_key)
            messagebox.showinfo("Server Response",data.get('message'))
        else:
            messagebox.showerror("Error",data.get('message'))
    except socket.error as e:
        messagebox.showerror("Connection Error", e)
    except Exception as e:
        messagebox.showerror("Error", f"An error has occurred: {e}")




def send_marks(subject_file_path, subject_name, role, client_socket, session_key, client_private_key):
    try:
        action='send_marks'
        
        subject_file=pd.read_excel(subject_file_path)
        subject_file.dropna(inplace=True)
        student_names= subject_file['name'].astype(str).tolist()
        student_marks= pd.to_numeric(subject_file['mark'], errors='coerce').astype('Int64')
        student_marks=student_marks.astype(str).replace('<NA>', '').tolist() 

        merge_all_data= ' '.join([subject_name]+student_names+student_marks)
        hashed_data= hash_string(merge_all_data)
        doctor_signature= sign_message(hashed_data, client_private_key).decode('latin-1')
        # doctor_signature= base64.b64decode(doctor_signature)
        enc_subject_name= symmetric_encryption(subject_name, session_key)        
        enc_student_names= symmetric_encryption(student_names, session_key)
        enc_student_marks= symmetric_encryption(student_marks, session_key)


        request= {'action':action,'data':hashed_data,'signature':doctor_signature, 'subject_name':enc_subject_name,
                   'students_names':enc_student_names,'students_marks':enc_student_marks}
        client_socket.send(json.dumps(request).encode())
        response= client_socket.recv(1024).decode()
        data= json.loads(response)
        
        status= data.get('status')
        if status == 200:
            data=symmetric_decryption(data,session_key)
            messagebox.showinfo("Server Response",data.get('message'))
        else:
            messagebox.showerror("Error",data.get('message'))
    except socket.error as e:
        messagebox.showerror("Connection Error", e)
    except Exception as e:
        messagebox.showerror("Error", f"An 00error has occurred: {e}")



def clear_widgets(frame):
    for widget in frame.winfo_children():
        widget.destroy()


def Student_or_Professor(frame,role,client_socket,session_key,client_private_key):
    if role == '1':
        Student_Frame(frame,role,client_socket,session_key)
    elif role == '2':
        Professor_Frame(frame, role, client_socket, session_key,client_private_key)


def Main_Frame():
    main_frame.tkraise()
    main_frame.grid_propagate(False)

    entry_username_value=tk.StringVar()
    entry_password_value=tk.StringVar()

    tk.Label(main_frame, text="Server IP:").grid(row=0, column=0, padx=5, pady=5)
    entry_ip = tk.Entry(main_frame)
    entry_ip.insert(0,'127.0.0.1')
    entry_ip.grid(row=0, column=1, padx=5, pady=5)

    tk.Label(main_frame, text="Server Port:").grid(row=1, column=0, padx=5, pady=5)
    entry_port = tk.Entry(main_frame)
    entry_port.insert(0,'5000')

    entry_port.grid(row=1, column=1, padx=5, pady=5)

    tk.Label(main_frame, text="Username:").grid(row=2, column=0, padx=5, pady=5)
    entry_username = tk.Entry(main_frame,textvariable=entry_username_value)
    entry_username.grid(row=2, column=1, padx=5, pady=5)

    tk.Label(main_frame, text="Password:").grid(row=3, column=0, padx=5, pady=5)
    entry_password = tk.Entry(main_frame,textvariable=entry_password_value ,show="*")
    entry_password.grid(row=3, column=1, padx=5, pady=5)

    button_login = tk.Button(main_frame, text="Create Account",
                             command=lambda: create_account(entry_ip, entry_port, entry_username_value, entry_password_value))
    button_login.grid(row=4, column=0, pady=10)

    button_create_account = tk.Button(main_frame, text="Login",
                                      command=lambda: login(entry_ip, entry_port, entry_username_value, entry_password_value))
    button_create_account.grid(row=4, column=1, pady=10)


def show_encryption_key(encryption_key):
    dialog = tk.Toplevel(root)
    dialog.title("Encryption Key")

    label = tk.Label(dialog, text=f"Encryption Key: {encryption_key}")
    label.grid(padx=20, pady=20)

    copy_button = tk.Button(dialog, text="Copy to Clipboard", command=lambda: copy_to_clipboard(encryption_key,dialog))
    copy_button.grid()


def Complete_Information_Frame(client_socket, username):
    clear_widgets(main_frame)
    complete_information_frame.tkraise()
    complete_information_frame.grid_propagate(False)
    

    tk.Label(complete_information_frame, text="Phone Number:").grid(row=0, column=0, padx=5, pady=5)
    entry_phone_number = tk.Entry(complete_information_frame)
    entry_phone_number.grid(row=0, column=1, padx=5, pady=5)

    tk.Label(complete_information_frame, text="Address:").grid(row=1, column=0, padx=5, pady=5)
    entry_address = tk.Entry(complete_information_frame)
    entry_address.grid(row=1, column=1, padx=5, pady=5)

    tk.Label(complete_information_frame, text="National Number:").grid(row=2, column=0, padx=5, pady=5)
    entry_national_number = tk.Entry(complete_information_frame)
    entry_national_number.grid(row=2, column=1, padx=5, pady=5)

    entry_role = tk.StringVar()

    Radiobutton(complete_information_frame, text='Student',
                variable=entry_role, value='1').grid(row=3, column=0, sticky=W)
    Radiobutton(complete_information_frame, text='Professor',
                variable=entry_role, value='2').grid(row=3, column=1, sticky=W)
    entry_role.set('1')

    tk.Label(complete_information_frame, text="Encryption Key:").grid(row=4, column=0, padx=5, pady=5)
    entry_key = tk.Entry(complete_information_frame)
    entry_key.grid(row=4, column=1, padx=5, pady=5)

    button_continue = tk.Button(complete_information_frame, text="Continue",
                                command=lambda: complete_information(username, client_socket, entry_phone_number,
                                                                     entry_national_number, entry_address, entry_role,
                                                                     entry_key))
    button_continue.grid(row=5, column=1, pady=10)

def Create_Client_Keys_Frame(username, client_socket,role):
    
    def save_file(username):

        file_path = filedialog.asksaveasfilename(defaultextension=".pem",initialfile=f"{username}_private_key.pem" , filetypes=[("PEM files", "*.pem")])
        
        client_private_key_path.set(file_path)


    clear_widgets(main_frame)
    
    create_client_keys_frame.tkraise()
    create_client_keys_frame.grid_propagate(False)

    client_private_key_path=tk.StringVar()

    save_public_key_button = tk.Button(create_client_keys_frame, text="Save Private Key File",
                                        command=lambda:save_file(username))
    save_public_key_button.grid(row=1, column= 0, pady=10)
    # save_private_key_button = tk.Button(create_client_keys_frame, text="Save Private Key File", command=lambda:save_file(2, username))
    # save_private_key_button.grid(row=2, column= 0, pady=10)
    
    button_continue = tk.Button(create_client_keys_frame, text="Continue", command=lambda:
                                generate_user_keys(client_socket, role, client_private_key_path.get()))
    button_continue.grid(row=3, column=1, pady=10)


def Load_Client_Keys_Frame(client_socket,role,username):

    def load_file(key):
        file_path = filedialog.askopenfilename(title="Select an .pem file", filetypes=[("PEM files", "*.pem")])
        if key==1:
            client_public_key_path.set(file_path)
        elif key==2:
            client_private_key_path.set(file_path)

    def empty_path(client_public_key_path,client_private_key_path,client_socket,role):
        client_public_key_path_value=client_public_key_path.get()
        client_private_key_path_value=client_private_key_path.get()
        print(client_public_key_path)
        print(client_private_key_path)

        if client_public_key_path_value.strip() and client_private_key_path_value.strip():
           handshake_client(client_socket, load_keys_frame,role,client_private_key_path_value)
        else:
             messagebox.showerror('Error', 'empty path')  

    clear_widgets(main_frame)
    load_keys_frame.tkraise()
    load_keys_frame.grid_propagate(False)

    client_public_key_path = tk.StringVar()
    client_private_key_path = tk.StringVar()

    load_public_key_button = tk.Button(load_keys_frame, text="Load Public Key File", command=lambda:load_file(1))
    load_public_key_button.grid(row=1, column= 0, pady=10)
    load_private_key_button = tk.Button(load_keys_frame, text="Load Private Key File", command=lambda:load_file(2))
    load_private_key_button.grid(row=2, column= 0, pady=10)

    button_continue = tk.Button(load_keys_frame, text="Continue", command=lambda:
                                empty_path(client_public_key_path,client_private_key_path,client_socket,role))
    button_continue.grid(row=3, column=1, pady=10)



# def load_keys():
#     clear_widgets(create_client_keys_frame)

#     load_keys_frame.tkraise()
#     load_keys_frame.grid_propagate(False)
#     load_keys_frame.title("File Loader")

#     load_public_key_button = tk.Button(load_keys_frame, text="Load Public Key File", command=lambda:load_file(1))
#     load_public_key_button.grid(row=1, column= 0, pady=10)
#     load_private_key_button = tk.Button(load_keys_frame, text="Load Private Key File", command=lambda:load_file(2))
#     load_private_key_button.grid(row=2, column= 0, pady=10)

def send_project_frame(role,client_socket,session_key):
    
    def add_another_project():
           
        if project_name_entry_value.get().strip() and project_info_entry_value.get().strip():
          
            project_name= project_name_entry_value.get()
            project_info= project_info_entry_value.get()
         
            projects.append((project_name, project_info))
            project_name_entry.delete(0, tk.END)
            project_info_entry.delete(0, tk.END)
          
        else:
            messagebox.showerror('Error', 'Empty input') 

    def check_projects():
        if not projects:
            messagebox.showerror("Error", "No Projects been added")
        else:
            send_project(projects,role,client_socket,session_key)
            send.destroy()


    send=tk.Toplevel(root)
    send.title("Project Description")
    
    projects= []
    project_name_entry_value=tk.StringVar()
    project_info_entry_value=tk.StringVar()

    tk.Label(send, text="Project Name:").grid(row=0, column=0, padx=5, pady=5)
    project_name_entry = tk.Entry(send,textvariable=project_name_entry_value,width=50, bd=2)
    project_name_entry.grid(row=0, column=1, padx=5, pady=5)

    tk.Label(send, text="Project Description:").grid(row=1, column=0, padx=5, pady=5)
    project_info_entry = tk.Entry(send, textvariable=project_info_entry_value,width=50, bd=2)
    project_info_entry.grid(row=1, column=1, padx=5, pady=5)

    send_button=tk.Button(send, text="Add", command=lambda: add_another_project())
    send_button.grid(row=2, column=0, pady=10)
    send_button=tk.Button(send, text="Send", command=lambda: check_projects())
    send_button.grid(row=2, column=1, pady=10)



def Student_Frame(frame,role,client_socket,session_key):
    
    clear_widgets(frame)
    
    student_frame.tkraise()
    student_frame.grid_propagate(False)

    enter_projcet_button = tk.Button(student_frame, text="Enter Project",
                                      command= lambda: send_project_frame(role,client_socket,session_key))
    enter_projcet_button.grid(row=0, column= 1, pady=10)

    show_marks_button= tk.Button(student_frame, text="Show Marks")
    show_marks_button.grid(row=1, column= 0, pady=10)

def Professor_Frame(frame,role,client_socket,session_key,client_private_key):
    clear_widgets(frame)
    
    professor_frame.tkraise()
    professor_frame.grid_propagate(False)

    enter_marks_button = tk.Button(professor_frame, text="Enter Marks",
                                      command= lambda: send_subject_frame(client_socket,session_key,role,client_private_key))
    enter_marks_button.grid(row=0, column= 1, pady=10)

def send_subject_frame(client_socket,session_key,role,client_private_key):
    def add_mark_file():
        subject_file_path.set(filedialog.askopenfilename(title="Select an .xlsx file",
                                                          filetypes=[("Excel Workbook", "*.xlsx")]))
        

    def check_marks():
        if subject_entry_value.get().strip():
            send_marks(subject_file_path.get(),subject_entry_value.get(),role,client_socket,session_key,client_private_key)
            send_marks_widget.destroy()
        else:
            messagebox.showerror('Error', 'Empty input') 

    

    send_marks_widget=tk.Toplevel(root)
    send_marks_widget.title("Project Description")
    
    subject_file_path=tk.StringVar()
    subject_entry_value=tk.StringVar()

    tk.Label(send_marks_widget, text="subject Name:").grid(row=0, column=0, padx=5, pady=5)

    subject_entry = tk.Entry(send_marks_widget,textvariable=subject_entry_value,width=50, bd=2)
    subject_entry.grid(row=0, column=1, padx=5, pady=5)

   
    add_marks_button=tk.Button(send_marks_widget, text="Add", command=lambda: add_mark_file())
    add_marks_button.grid(row=2, column=0, pady=10)
    send_marks_button=tk.Button(send_marks_widget, text="Send", command=lambda: check_marks())
    send_marks_button.grid(row=2, column=1, pady=10)


root = tk.Tk()

root.title("Welcome")
root.eval("tk::PlaceWindow . center")

# x = root.winfo_screenwidth() // 3
# y = int(root.winfo_screenheight() * 0.2)
# root.geometry('300x400+' + str(x) + '+' + str(y))
root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=0)
root.grid_columnconfigure(0, weight=1)

# create a frame widgets
main_frame = tk.Frame(root, width=300, height=400, bg="#3d6466")
complete_information_frame = tk.Frame(root,width=300, height=400, bg="#3d6466")
load_keys_frame = tk.Frame(root,width=300, height=400, bg="#3d6466")
create_client_keys_frame = tk.Frame(root,width=300, height=400, bg="#3d6466")
student_frame = tk.Frame(root,width=300, height=400, bg="#3d6466")
professor_frame = tk.Frame(root,width=300, height=400, bg="#3d6466")


for frame in (main_frame, complete_information_frame,load_keys_frame, create_client_keys_frame, student_frame, professor_frame):
    frame.grid(row=0, column=0, sticky="nesw")
if __name__== '__main__':
    Main_Frame()
    root.mainloop()
