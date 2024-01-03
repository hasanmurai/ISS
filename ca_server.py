import json
import socket
import ssl
import threading
from asymmetric import generate_rsa_keys, verify_signature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption



def generate_ca_certificate():
    
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"My CA"),
    ])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(datetime.utcnow())
    builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10 years validity
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(ca_private_key.public_key())
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )

    ca_certificate_ = builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    return ca_certificate_

def sign_certificate_request(csr):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ca_certificate.subject)
    builder = builder.not_valid_before(datetime.utcnow())
    builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365))  # 1-year validity for the signed certificate
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(ca_private_key.public_key())
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )

    signed_certificate = builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return signed_certificate


def handle_client(client_socket):
    request= client_socket.recv(4000).decode()
    data= json.loads(request)
    sender= data.get('sender')
    if sender == 'server':
        server_csr= data.get('csr')
        server_csr= x509.load_pem_x509_csr(server_csr.encode(), default_backend())
        server_signed_certificate= sign_certificate_request(server_csr)
        
        response={'signed_certificate':server_signed_certificate.public_bytes(Encoding.PEM).decode(), 'status':200}
        client_socket.send(json.dumps(response).encode())
    
    elif sender == 'client':
        
        equation= '3 + 4 ='
        equation_answer= '7'
        doctor_csr= data.get('csr')
        doctor_csr= x509.load_pem_x509_csr(doctor_csr.encode(), default_backend())
        
        response={'action':'solve','equation':equation}
        client_socket.send(json.dumps(response).encode())
        request=client_socket.recv(4096).decode()
        
        data= json.loads(request)
        answer= data.get('answer').encode('latin-1')
        verify_answer= verify_signature(equation_answer, answer, doctor_csr.public_key())
        
        if verify_answer:            
            doctor_signed_certificate= sign_certificate_request(doctor_csr)
            response= {'signed_certificate':doctor_signed_certificate.public_bytes(Encoding.PEM).decode(), 'status':200}
            common_name_attribute = None
            for attribute in doctor_signed_certificate.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    common_name_attribute = attribute
                    break
            print(f'create certificate for{common_name_attribute.value}')
        
        else:
            response= {'message':'signature failed','status':400}
       
        client_socket.send(json.dumps(response).encode())
    
    else:        
        response = {"message": "Invalid action",'status':400}
        client_socket.send(json.dumps(response).encode())
        client_socket.close()


def ca_server():
    

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 5001))
    server_socket.listen()
    global ca_private_key, ca_certificate
    ca_private_key = generate_rsa_keys()
    ca_certificate = generate_ca_certificate()

    print("CA Server listening on port 5001")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()


if __name__ == "__main__":
    ca_server()
