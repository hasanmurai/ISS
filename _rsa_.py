import base64
import os
import rsa

def generate_rsa_keys():
    public_key, private_key= rsa.newkeys(1024)
    return public_key, private_key

def save_keys_to_file(key, key_path):
    with open(key_path, 'wb') as file:
        file.write(key.save_pkcs1("PEM"))
    
def load_public_key(key_path):
    if os.path.exists(key_path):
        with open(key_path,'rb') as file:
            public_key= rsa.PublicKey.load_pkcs1(file.read())
            return public_key
    else:
        print(f"Key file not found: {key_path}")

def load_private_key(key_path):
    if os.path.exists(key_path):
        with open(key_path,'rb') as file:
            private_key= rsa.PrivateKey.load_pkcs1(file.read())
            return private_key
    else:
        print(f"Key file not found: {key_path}")

def rsa_encrypt(message, public_key):
    encrypted_message= rsa.encrypt(message.encode(), public_key)
    return encrypted_message

def rsa_decrypt(encrypted_message, private_key):
    decrypted_message= rsa.decrypt(encrypted_message, private_key)
    return decrypted_message.decode()    

def rsa_signature(data, private_key):
    signature = rsa.sign(data.encode(), private_key, 'SHA-256')
    return signature


def rsa_verify_signature(data, signature, public_key):
    try:
        rsa.verify(data.encode(), signature, public_key)
        return True
    except rsa.VerificationError:
        return False