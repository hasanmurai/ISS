import os

def generate_pgp_keys(gpg, name, email, passphrase):
    # Generate a new PGP key pair
    input_data = gpg.gen_key_input(
        key_type="RSA",
        key_length=2048,
        name_real=name,
        name_email=email,
        passphrase=passphrase
    )
    key = gpg.gen_key(input_data)
    return key

def save_key_to_file(gpg, key, key_type, passphrase, file_path):
    # Extract the key details to obtain the fingerprint
    key_details = gpg.list_keys(keys=[key.fingerprint], secret=key_type == 'sec')

    if key_details:
        key_fingerprint = key_details[0]['fingerprint']
        
        # Export the key to a file, providing the passphrase for secret keys
        if key_type == 'sec':
            # Export the secret key
            key_data = gpg.export_keys(key_fingerprint, secret=True, passphrase=passphrase)
        else:
            # Export the public key
            key_data = gpg.export_keys(key_fingerprint)

        # Save the key to a file
        with open(file_path, 'wb') as key_file:  # Use 'wb' for binary mode
            key_file.write(key_data.encode('utf-8'))
    else:
        print("Key details not found.")

def load_key_from_file(gpg, key_path):
    # Check if the file exists
    if os.path.exists(key_path):
        # Read key data from the file
        with open(key_path, 'rb') as key_file:
            key_data = key_file.read().decode('utf-8')

        # Import the key into the GPG instance
        gpg.import_keys(key_data)
    else:
        print(f"Key file not found: {key_path}")

def pgp_encryption(gpg, recipient_key_id, message):
    # Encrypt a message using the recipient's public key
    encrypted_data = gpg.encrypt(message, recipient_key_id)
    return str(encrypted_data)

def pgp_decryption(gpg, encrypted_message, passphrase):
    # Decrypt a message using the private key and passphrase
    decrypted_data = gpg.decrypt(encrypted_message, passphrase=passphrase)
    return str(decrypted_data)


#    recipient_public_key = gpg.export_keys(recipient_key.fingerprint)
#        encrypted_message = encrypt_message(gpg, recipient_public_key, message_to_encrypt)
  

#    recipient_private_key = gpg.export_keys(recipient_key.fingerprint, secret=True, passphrase="recipient_passphrase")
#    decrypted_message = decrypt_message(gpg, encrypted_message, "recipient_passphrase")













# if __name__ == "__main__":
#       # Make sure to import the os module

#     # Initialize GPG
#     gpg = gnupg.GPG()

#     # File paths for keys
#     recipient_public_key_path = 'recipient_public_key.asc'
#     recipient_private_key_path = 'recipient_private_key.asc'

#     # Generate PGP keys for the recipient
#     recipient_key = generate_key(gpg, "Recipient Name", "recipient@example.com", "recipient_passphrase")

#     # Save recipient public key to file
#     save_key_to_file(gpg, recipient_key, 'pub', None, recipient_public_key_path)

#     # Save recipient private key to file (provide passphrase for secret key)
#     save_key_to_file(gpg, recipient_key, 'sec', "recipient_passphrase", recipient_private_key_path)
#  # File paths for keys
#     # Load recipient public key from file
#     load_key_from_file(gpg, recipient_public_key_path)

#     # Load recipient private key from file
#     load_key_from_file(gpg, recipient_private_key_path)

#     # Message to be encrypted
#     message_to_encrypt = "Hello, this is a secret message!"

#     # Encrypt the message using the recipient's public key
#     encrypted_message = encrypt_message(gpg, recipient_key.fingerprint, message_to_encrypt)
#     print(f"Encrypted message: {encrypted_message}")

#     # Decrypt the message using the recipient's private key
#     decrypted_message = decrypt_message(gpg, encrypted_message, "recipient_passphrase")
#     print(f"Decrypted message: {decrypted_message}")