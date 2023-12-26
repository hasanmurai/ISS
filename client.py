import socket
import json
import hashlib
import gnupg
import tkinter as tk
from tkinter import W, Radiobutton, messagebox
from tkinter import filedialog
from symmetric_key import generate_symmetric_key, symmetric_encryption, symmetric_decryption
from pgp import generate_pgp_keys, pgp_encryption, pgp_decryption, save_key_to_file,load_key_from_file 


def hash(password):
    hash = hashlib.sha256()
    hash.update(password.encode() if isinstance(password, str) else password)
    hash_value = hash.hexdigest()
    return hash_value


def copy_to_clipboard(message):
    root.clipboard_clear()
    root.clipboard_append(message)
    root.update()


def create_account(entry_ip, entry_port, entry_username, entry_password):
    try:
        server_ip = entry_ip.get()
        server_port = int(entry_port.get())
        username = entry_username.get()
        password = hash(entry_password.get())

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
        messagebox.showerror("Connection Error", "No server available")
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
        password = hash(entry_password.get())

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, server_port))

        action = "login"
        request_data = {"action": action, "username": username, "password": password}
        client_socket.send(json.dumps(request_data).encode())

        response_data = client_socket.recv(1024).decode()
        response = json.loads(response_data)
        
        messagebox.showinfo("Server Response", response['message'])
        if response["status"]==200:
            Student_or_Professor(response['role'], "main_frame")
        else:
            client_socket.close()

    except socket.error as e:
        messagebox.showerror("Connection Error", "No server available")
        client_socket.close()
        root.destroy()
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

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
        if int(response['status'])==400:
            messagebox.showerror("Error", f"An error has occurred:ss")
            client_socket.close()
            root.destroy()
        else:
            
            messagebox.showinfo("Server Response", response['message'])
            
            Create_Client_Keys_Frame(username, client_socket)

            # Student_or_Professor(response["role"], "complete_information_frame")
            
    except socket.error as e:
        messagebox.showerror("Connection Error", "No server available")
    except Exception as e:
        messagebox.showerror("Error", f"An error has occurred: {e}")

    # finally:
    #     client_socket.close()
def generate_user_key(username, entry_passphrase, client_socket, user_public_key_path, user_private_key_path):
    
    try:
        passphrase= entry_passphrase.get()
        gpg = gnupg.GPG()
        client_keys= generate_pgp_keys(gpg, username, '', passphrase)

        save_key_to_file(gpg, client_keys, 'pub', None, user_public_key_path)
        save_key_to_file(gpg, client_keys, 'sec', passphrase, user_private_key_path)

        client_public_key = gpg.export_keys(client_keys.fingerprint)
        client_private_key = gpg.export_keys(client_keys.fingerprint, secret=True, passphrase=passphrase)
        print('dd')
        handshake_client(client_socket, client_public_key, gpg)
        # client_socket.send(json.dumps(client_public_key).encode())
        # response= client_socket.recv(1024).decode()
        # data= json.load(response)
        # if data["message"]:
        #     server_public_key=data.get("server_public_key")
    except Exception as e:
        messagebox.showerror("Error", f"An error has occurred: {e}")
        client_socket.close()
        root.destroy()


def handshake_client(client_socket, client_public_key,gpg):
    try:
        request = {"client_public_key": client_public_key}
        client_socket.send(json.dumps(request).encode())
        response= client_socket.recv(2048).decode()
        data= json.loads(response)
        if data['message']==True:
            server_public_key= data.get("server_public_key")
            create_session_key(client_socket, server_public_key, gpg)
        else:    
            messagebox.showerror("Error",data.get('message'))
    except Exception as e:
        messagebox.showerror("Error", f"An error has occurred: {e}")
        client_socket.close()
        root.destroy()

def create_session_key(client_socket, server_public_key, gpg):
    session_key= generate_symmetric_key()
    encrypt_session_key= pgp_encryption(gpg, session_key.decode(), server_public_key)
    response= {'message': True, "session_key": encrypt_session_key}
    client_socket.send(json.dumps(response).encode())


def load_file(key):
    file_path = filedialog.askopenfilename(title="Select an .asc file", filetypes=[("ASC files", "*.asc")])
    if key==1:
        global client_public_key_path
        client_public_key_path = file_path
    elif key==2:
        global client_private_key_path
        client_private_key_path = file_path

def save_file(key, username):
    if key==1:
        file_path = filedialog.asksaveasfilename(defaultextension=".asc",initialfile=f"{username}_public_key.asc" , filetypes=[("ASC files", "*.asc")])
        global client_public_key_path 
        client_public_key_path = file_path
    
        file_path = filedialog.asksaveasfilename(defaultextension=".asc",initialfile=f"{username}_private_key.asc" , filetypes=[("ASC files", "*.asc")])
        global client_private_key_path
        client_private_key_path = file_path




def clear_widgets(frame):
    for widget in frame.winfo_children():
        widget.destroy()


def Student_or_Professor(role, frame):
    if role == '1':
        Student_Frame(frame)
    else:
        Professor_Frame(frame)


def Main_Frame():
    main_frame.tkraise()
    main_frame.grid_propagate(False)

    tk.Label(main_frame, text="Server IP:").grid(row=0, column=0, padx=5, pady=5)
    entry_ip = tk.Entry(main_frame)
    entry_ip.grid(row=0, column=1, padx=5, pady=5)

    tk.Label(main_frame, text="Server Port:").grid(row=1, column=0, padx=5, pady=5)
    entry_port = tk.Entry(main_frame)
    entry_port.grid(row=1, column=1, padx=5, pady=5)

    tk.Label(main_frame, text="Username:").grid(row=2, column=0, padx=5, pady=5)
    entry_username = tk.Entry(main_frame)
    entry_username.grid(row=2, column=1, padx=5, pady=5)

    tk.Label(main_frame, text="Password:").grid(row=3, column=0, padx=5, pady=5)
    entry_password = tk.Entry(main_frame, show="*")
    entry_password.grid(row=3, column=1, padx=5, pady=5)

    button_login = tk.Button(main_frame, text="Create Account",
                             command=lambda: create_account(entry_ip, entry_port, entry_username, entry_password))
    button_login.grid(row=4, column=0, pady=10)

    button_create_account = tk.Button(main_frame, text="Login",
                                      command=lambda: login(entry_ip, entry_port, entry_username, entry_password))
    button_create_account.grid(row=4, column=1, pady=10)


def show_encryption_key(encryption_key):
    dialog = tk.Toplevel(root)
    dialog.title("Encryption Key")

    label = tk.Label(dialog, text=f"Encryption Key: {encryption_key}")
    label.grid(padx=20, pady=20)

    copy_button = tk.Button(dialog, text="Copy to Clipboard", command=lambda: copy_to_clipboard(encryption_key))
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

def Create_Client_Keys_Frame(username, client_socket):
    clear_widgets(main_frame)
    
    create_client_keys_frame.tkraise()
    create_client_keys_frame.grid_propagate(False)

    tk.Label(create_client_keys_frame, text="Enter passphrase:").grid(row=0, column=0, padx=5, pady=5)
    entry_passphrase = tk.Entry(create_client_keys_frame)
    entry_passphrase.grid(row=0, column=1, padx=5, pady=5)

    save_public_key_button = tk.Button(create_client_keys_frame, text="Save Public Key File", command=lambda:save_file(1, username))
    save_public_key_button.grid(row=1, column= 0, pady=10)
    # save_private_key_button = tk.Button(create_client_keys_frame, text="Save Private Key File", command=lambda:save_file(2, username))
    # save_private_key_button.grid(row=2, column= 0, pady=10)
    
    button_continue = tk.Button(create_client_keys_frame, text="Continue", command=lambda:
                                generate_user_key(username, entry_passphrase, client_socket,
                                                   client_public_key_path,client_private_key_path))
    button_continue.grid(row=3, column=1, pady=10)



def load_keys():
    clear_widgets(create_client_keys_frame)

    load_keys_frame.tkraise()
    load_keys_frame.grid_propagate(False)
    load_keys_frame.title("File Loader")

    load_public_key_button = tk.Button(load_keys_frame, text="Load Public Key File", command=lambda:load_file(1))
    load_public_key_button.grid(row=1, column= 0, pady=10)
    load_private_key_button = tk.Button(load_keys_frame, text="Load Private Key File", command=lambda:load_file(2))
    load_private_key_button.grid(row=2, column= 0, pady=10)



def Student_Frame(frame):
    if frame == "main_frame":
        clear_widgets(main_frame)
    else:
        clear_widgets(complete_information_frame)
    student_frame.tkraise()
    student_frame.grid_propagate(False)

    tk.Label(student_frame, text="asd Number:").grid(row=0, column=0, padx=5, pady=5)
    entry_phone_number = tk.Entry(student_frame)
    entry_phone_number.grid(row=0, column=1, padx=5, pady=5)


def Professor_Frame(frame):
    if frame == "main_frame":
        clear_widgets(main_frame)
    else:
        clear_widgets(complete_information_frame)
    professor_frame.tkraise()
    professor_frame.grid_propagate(False)

    tk.Label(professor_frame, text="Phone Number:").grid(row=0, column=0, padx=5, pady=5)
    entry_phone_number = tk.Entry(professor_frame)
    entry_phone_number.grid(row=0, column=1, padx=5, pady=5)


root = tk.Tk()
root.title("Welcome")
root.eval("tk::PlaceWindow . center")

# x = root.winfo_screenwidth() // 2
# y = int(root.winfo_screenheight() * 0.1)
# root.geometry('500x600+' + str(x) + '+' + str(y))

# create a frame widgets
main_frame = tk.Frame(root, width=500, height=600, bg="#3d6466")
complete_information_frame = tk.Frame(root, bg="#3d6466")
load_keys_frame = tk.Frame(root, bg="#3d6466")
create_client_keys_frame = tk.Frame(root, bg="#3d6466")
student_frame = tk.Frame(root, bg="#3d6466")
professor_frame = tk.Frame(root, bg="#3d6466")

for frame in (main_frame, complete_information_frame,load_keys_frame, create_client_keys_frame, student_frame, professor_frame):
    frame.grid(row=0, column=0, sticky="nesw")

Main_Frame()
root.mainloop()
