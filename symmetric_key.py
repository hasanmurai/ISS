from cryptography.fernet import Fernet

def generate_symmetric_key():
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
