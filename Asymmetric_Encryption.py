import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography import x509

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

    with open(key_path, 'wb') as private_key_file:
        private_key_file.write(private_key_to_str(private_key).encode())


def load_private_key_from_file(key_path):

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

def generate_csr(private_key, common_name):
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"My Organization"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
    ]))
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())

    return csr

def save_certificate(certificate, file_path):
    with open(file_path, "wb") as cert_file:
        cert_file.write(certificate.public_bytes(Encoding.PEM))

def load_certificate(file_path):
    with open(file_path, "rb") as cert_file:
        certificate_data = cert_file.read()
    certificate = x509.load_pem_x509_certificate(certificate_data, default_backend())
    return certificate

def verify_certificate(certificate, public_key):
    try:
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
        return True
    except Exception as e:
        print(f"Verification failed")
        return False