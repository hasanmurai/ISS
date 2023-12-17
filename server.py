import socket
import json
import sqlite3
import threading

DATABASE_NAME = "accounts.db"

def create_table():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Create a table to store accounts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    ''')

    conn.commit()
    conn.close()

def account_exists(username):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM accounts WHERE username=?", (username,))
    account = cursor.fetchone()
    conn.close()

    return account is not None


def handle_client(client_socket):
    create_table()

    data = client_socket.recv(1024).decode("utf-8")
    request = json.loads(data)

    action = request.get("action")
    username = request.get("username")
    password = request.get("password")

    if action == "create_account":
        conn = None  # Initialize conn here

        try:
            if account_exists(username):
                response = {"status": "Username already exists"}
            else:
                conn = sqlite3.connect(DATABASE_NAME)
                cursor = conn.cursor()
                cursor.execute('INSERT INTO accounts (username, password) VALUES (?, ?)', (username, password))
                conn.commit()
                response = {"status": "Account created successfully"}
        except sqlite3.Error as e:
            response = {"status": f"Error creating account: {str(e)}"}
        finally:
            if conn:
                conn.close()

    elif action == "login":
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM accounts WHERE username=? AND password=?', (username, password))
            account = cursor.fetchone()

            if account:
                response = {"status": "Login successful"}
            else:
                response = {"status": "Invalid username or password"}
        except sqlite3.Error as e:
            response = {"status": f"Error during login: {str(e)}"}
        finally:
            conn.close()

    else:
        response = {"status": "Invalid action"}

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
