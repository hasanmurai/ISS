import socket
import ssl
import threading
from asymmetric import generate_rsa_keys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID


def sign_certificate_request(csr, ca_private_key, ca_certificate):
    issuer = ca_certificate.subject
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(csr.not_valid_before)
    builder = builder.not_valid_after(csr.not_valid_after)

    certificate = builder.sign(
        ca_private_key, hashes.SHA256(), default_backend()
    )

    return certificate

def handle_entity(connection, ca_private_key, ca_certificate):
    print("Handling connection")

    # Receive entity name and CSR from the entity
    entity_name = connection.recv(1024).decode('utf-8')
    csr_data = connection.recv(4096)
    csr = x509.load_pem_x509_csr(csr_data, default_backend())

    # Sign CSR and send the signed certificate to the entity
    signed_certificate = sign_certificate_request(csr, ca_private_key, ca_certificate)
    connection.sendall(signed_certificate.public_bytes(encoding=serialization.Encoding.PEM))

    connection.close()

def ca_server():
    ca_private_key = generate_rsa_keys()

    # Self-sign the CA certificate
    ca_certificate = sign_certificate_request(ca_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ), ca_private_key, None)

    # Setup CA server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8888))
    server_socket.listen(5)  # Allow connections from 5 entities

    print("CA Server listening on port 8888")

    while True:
        connection, address = server_socket.accept()
        ssl_connection = ssl.wrap_socket(
            connection,
            keyfile=None,
            certfile=None,
            server_side=True,
            cert_reqs=ssl.CERT_NONE,  # Adjust based on your security requirements
            ssl_version=ssl.PROTOCOL_TLS
        )

        threading.Thread(target=handle_entity, args=(ssl_connection, ca_private_key, ca_certificate)).start()

if __name__ == "__main__":
    ca_server()
