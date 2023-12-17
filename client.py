import tkinter as tk
from tkinter import messagebox
import socket
import json

def send_request(action, username, password):
    request = {"action": action, "username": username, "password": password}
    return json.dumps(request).encode("utf-8")

def create_account():
    try:
        server_ip = entry_ip.get()
        server_port = int(entry_port.get())
        username = entry_username.get()
        password = entry_password.get()

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, server_port))

        action = "create_account"
        request_data = send_request(action, username, password)
        client_socket.send(request_data)

        response_data = client_socket.recv(1024).decode("utf-8")
        response = json.loads(response_data)

        messagebox.showinfo("Server Response", response['status'])

    except socket.error as e:
        messagebox.showerror("Connection Error", "No server available")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

    finally:
        client_socket.close()

def login():
    try:
        server_ip = entry_ip.get()
        server_port = int(entry_port.get())
        username = entry_username.get()
        password = entry_password.get()

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, server_port))

        action = "login"
        request_data = send_request(action, username, password)
        client_socket.send(request_data)

        response_data = client_socket.recv(1024).decode("utf-8")
        response = json.loads(response_data)

        messagebox.showinfo("Server Response", response['status'])

    except socket.error as e:
        messagebox.showerror("Connection Error", "No server available")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

    finally:
        client_socket.close()

# GUI setup
root = tk.Tk()
root.title("Client Interface")

frame = tk.Frame(root)
frame.pack(padx=20, pady=20)

tk.Label(frame, text="Server IP:").grid(row=0, column=0, padx=5, pady=5)
entry_ip = tk.Entry(frame)
entry_ip.grid(row=0, column=1, padx=5, pady=5)

tk.Label(frame, text="Server Port:").grid(row=1, column=0, padx=5, pady=5)
entry_port = tk.Entry(frame)
entry_port.grid(row=1, column=1, padx=5, pady=5)

tk.Label(frame, text="Username:").grid(row=2, column=0, padx=5, pady=5)
entry_username = tk.Entry(frame)
entry_username.grid(row=2, column=1, padx=5, pady=5)

tk.Label(frame, text="Password:").grid(row=3, column=0, padx=5, pady=5)
entry_password = tk.Entry(frame, show="*")
entry_password.grid(row=3, column=1, padx=5, pady=5)

button_create_account = tk.Button(frame, text="Create Account", command=create_account)
button_create_account.grid(row=4, column=0, pady=10)

button_login = tk.Button(frame, text="Login", command=login)
button_login.grid(row=4, column=1, pady=10)

root.mainloop()
