import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import Name, NameAttribute, CertificateSigningRequestBuilder
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    return private_key

def public_key_to_str(public_key):
    return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

def private_key_to_str(private_key):
    return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

def str_to_public_key(key):
    return serialization.load_pem_public_key(key.encode(), backend=default_backend())

def str_to_private_key(key):
    return serialization.load_pem_private_key(key.encode(), password=None, backend=default_backend())     



def save_private_key_to_file(private_key, key_path):
    # Save public key to a file
    # with open('your_public_key.pem', 'wb') as public_key_file:
    #     public_key_file.write(public_key.public_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PublicFormat.SubjectPublicKeyInfo
    #     ))

    # Save private key to a file (Keep private key secure and do not share)
    with open(key_path, 'wb') as private_key_file:
        private_key_file.write(private_key_to_str(private_key).encode())


def load_private_key_from_file(key_path):
    # Load keys from files
    # with open('your_public_key.pem', 'rb') as public_key_file:
    #     public_key = serialization.load_pem_public_key(public_key_file.read(), backend=default_backend())
    if os.path.exists(key_path):
        with open(key_path, 'rb') as private_key_file:
            private_key = serialization.load_pem_private_key(private_key_file.read(), password=None, backend=default_backend())

        return private_key
    else:
        return False

def asymmetric_encryption(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def asymmetric_decryption(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')


def sign_message(message, private_key):
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

