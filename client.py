import hashlib
import tkinter as tk
from tkinter import W, Radiobutton, messagebox
import socket
import json
from cryptography.fernet import Fernet


def symmetric_encryption(data, key):
    fernet = Fernet(key.encode())
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
            Complete_Information_Frame(client_socket)


    except socket.error as e:
        messagebox.showerror("Connection Error", "No server available")
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
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

    # finally:
    #     client_socket.close()


def complete_information(_client_socket_, entry_phone_number,
                         entry_national_number, entry_address, entry_role, entry_key):
    try:
        
        client_socket = _client_socket_

        phone_number = entry_phone_number.get()
        national_number = entry_national_number.get()
        address = entry_address.get()
        role = entry_role.get()
        key = entry_key.get()
        request_data = {"phone_number": phone_number, "national_number": national_number,
                        "address": address, "role": role}
   
        encrypted_data = symmetric_encryption(request_data, key)
      

        # client_socket.send(json.dumps(encrypted_data).encode())
        # response_json = json.dumps(encrypted_data, default=lambda x: str(x))
        client_socket.send(json.dumps(encrypted_data).encode())

        response_data = client_socket.recv(1024).decode()
        response = json.loads(response_data)
        response = symmetric_decryption(response,key)
        messagebox.showinfo("Server Response", response['message'])
        Student_or_Professor(response["role"], "complete_information_frame")

    except socket.error as e:
        messagebox.showerror("Connection Error", "No server available")
    except Exception as e:
        messagebox.showerror("Error", f"An error has occurred: {e}")

    # finally:
    #     client_socket.close()


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
    main_frame.pack_propagate(False)

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
    label.pack(padx=20, pady=20)

    copy_button = tk.Button(dialog, text="Copy to Clipboard", command=lambda: copy_to_clipboard(encryption_key))
    copy_button.pack()


def Complete_Information_Frame(client_socket):
    clear_widgets(main_frame)
    complete_information_frame.tkraise()
    complete_information_frame.pack_propagate(False)

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
                                command=lambda: complete_information(client_socket, entry_phone_number,
                                                                     entry_national_number, entry_address, entry_role,
                                                                     entry_key))
    button_continue.grid(row=5, column=1, pady=10)


def Student_Frame(frame):
    if frame == "main_frame":
        clear_widgets(main_frame)
    else:
        clear_widgets(student_frame)
    student_frame.tkraise()
    student_frame.pack_propagate(False)

    tk.Label(student_frame, text="asd Number:").grid(row=0, column=0, padx=5, pady=5)
    entry_phone_number = tk.Entry(student_frame)
    entry_phone_number.grid(row=0, column=1, padx=5, pady=5)


def Professor_Frame(frame):
    if frame == "main_frame":
        clear_widgets(main_frame)
    else:
        clear_widgets(professor_frame)
    professor_frame.tkraise()
    professor_frame.pack_propagate(False)

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
student_frame = tk.Frame(root, bg="#3d6466")
professor_frame = tk.Frame(root, bg="#3d6466")

for frame in (main_frame, complete_information_frame, student_frame, professor_frame):
    frame.grid(row=0, column=0, sticky="nesw")

Main_Frame()
root.mainloop()
