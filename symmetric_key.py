import hashlib
from cryptography.fernet import Fernet

def hash_string(password):
    hash = hashlib.sha256()
    hash.update(password.encode() if isinstance(password, str) else password)
    hash_value = hash.hexdigest()
    return hash_value

def generate_symmetric_key():
    key=Fernet.generate_key()
    return key

def symmetric_encryption(data, key):
    fernet = Fernet(key)
    
    if isinstance(data, dict):
        encrypted_data = {}
    
        for field, value in data.items():
    
            if field=="status":
                encrypted_data[field] = value
            
            else:
                encrypted_data[field] = fernet.encrypt(value.encode()).decode()
    
    elif isinstance(data, list):    
        encrypted_data= []
    
        if isinstance(data[0],tuple):
            encrypted_data=[tuple(fernet.encrypt(value.encode()).decode() for value in tup) for tup in data]
        
        elif isinstance(data[0],str):
            encrypted_data=[fernet.encrypt(x.encode()).decode() for x in data]
    
    elif isinstance(data,str):
        encrypted_data= fernet.encrypt(data.encode()).decode()

    return encrypted_data

def symmetric_decryption(encrypted_data, key):
    fernet = Fernet(key)
    
    if isinstance(encrypted_data, dict):
        decrypted_data = {}

        for field, value in encrypted_data.items():
            
            if field=="status":
                decrypted_data[field] = value
        
            else:
                decrypted_data[field] = fernet.decrypt(value).decode()  
    
    elif isinstance(encrypted_data, list):
        decrypted_data= []
        
        if isinstance(encrypted_data[0],tuple):
            decrypted_data=[tuple(fernet.decrypt(value).decode() for value in tup) for tup in encrypted_data]
        
        elif isinstance(encrypted_data[0],str):
            decrypted_data=[fernet.decrypt(x).decode() for x in encrypted_data]

    elif isinstance(encrypted_data,str):
        decrypted_data= fernet.decrypt(encrypted_data).decode()    
    
    return decrypted_data
