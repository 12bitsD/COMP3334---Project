from LoginController import *
import hmac
from CryptographyController import *
import config
import requests

def header_enc(filename):
    cipher_username = encrypt_with_public_key(config.GLOBAL_CONFIG['username'], config.GLOBAL_CONFIG['public_key']).hex()
    cipher_filename = encrypt_with_public_key(filename, config.GLOBAL_CONFIG['public_key']).hex()
    pwd = hashlib.sha256(f"{config.GLOBAL_CONFIG['username'] + config.GLOBAL_CONFIG['password']}".encode("utf-8")).hexdigest()
    return cipher_username, cipher_filename, pwd

def upload(filename):
    with open("content.txt", "r", encoding="utf-8") as f:
        plaintext = f.read()
    ciphertext = encrypt_with_public_key(plaintext, config.GLOBAL_CONFIG['public_key']).hex()
    cipher_username, cipher_filename, pwd = header_enc(filename)

    all_message = "action" + cipher_username + cipher_filename + ciphertext + pwd
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = config.GLOBAL_CONFIG['shared_key'].encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()

    data = {
        "username": cipher_username,
        "auth": pwd,
        "filename": cipher_filename,
        "encrypted_content": ciphertext,
        "hmac": hmac_result
    }
    
    response = requests.post(f"{base_url}/files/upload", json=data).json()
    
    if response["status"] == "success":
        print(f"File uploaded successfully. File ID: {response.get('file_id', 'unknown')}")
    else:
        print(f"Upload failed: {response.get('file', 'Unknown error')}")


def download(filename):
    cipher_username, cipher_filename, pwd = header_enc(filename)
    all_message = "download" + cipher_username + cipher_filename + pwd
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = config.GLOBAL_CONFIG['shared_key'].encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()

    params = {
        "username": cipher_username,
        "auth": pwd,
        "filename": cipher_filename,
        "hmac": hmac_result
    }
    
    response = requests.get(f"{base_url}/files/download", params=params).json()
    
    if response["status"] == "success":
        encrypted_content = bytes.fromhex(response["encrypted_content"])
        decrypted_text = decrypt_with_private_key(encrypted_content, config.GLOBAL_CONFIG['private_key'])
        print(decrypted_text)
    else:
        print(f"Download failed: {response.get('file', 'Unknown error')}")


def delete(filename):
    cipher_username, cipher_filename, pwd = header_enc(filename)

    all_message = "delete" + cipher_username + cipher_filename + pwd
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = config.GLOBAL_CONFIG['shared_key'].encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()

    params = {
        "username": cipher_username,
        "auth": pwd,
        "filename": cipher_filename,
        "hmac": hmac_result
    }
    
    response = requests.delete(f"{base_url}/files/delete", params=params).json()
    
    if response["status"] == "success":
        print("File deleted successfully.")
    else:
        print(f"Delete failed: {response.get('file', 'Unknown error')}")


def edit(filename, updated_content):
    cipher_username, cipher_filename, pwd = header_enc(filename)
    ciphertext = encrypt_with_public_key(updated_content, config.GLOBAL_CONFIG['public_key']).hex()

    all_message = "update" + cipher_username + cipher_filename + ciphertext + pwd
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = config.GLOBAL_CONFIG['shared_key'].encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()

    data = {
        "username": cipher_username,
        "auth": pwd,
        "filename": cipher_filename,
        "encrypted_content": ciphertext,
        "hmac": hmac_result
    }
    
    response = requests.put(f"{base_url}/files/update", json=data).json()
    
    if response["status"] == "success":
        print("File updated successfully.")
    else:
        print(f"Update failed: {response.get('file', 'Unknown error')}")


def ask_share(filename, to_user):
    cipher_username, cipher_filename, pwd = header_enc(filename)
    cipher_to_user = encrypt_with_public_key(to_user, config.GLOBAL_CONFIG['public_key']).hex()

    all_message = "ask_share" + cipher_username + cipher_filename + pwd + to_user
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = config.GLOBAL_CONFIG['shared_key'].encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()

    data = {
        "action": "ask_share",
        "username": cipher_username,
        "auth": pwd,
        "filename": cipher_filename,
        "to_user": cipher_to_user,
        "hmac": hmac_result
    }
    
    response = requests.post(f"{base_url}/files/ask_share", json=data).json()
    
    if response["status"] == "success":
        print(f"File share request sent. Target public key: {response.get('target_public_key', 'unknown')}")
    else:
        print(f"Share request failed: {response.get('file', 'Unknown error')}")


def confirm_share():
    cipher_username = encrypt_with_public_key(config.GLOBAL_CONFIG['username'], config.GLOBAL_CONFIG['public_key']).hex()
    pwd = hashlib.sha256(f"{config.GLOBAL_CONFIG['username'] + config.GLOBAL_CONFIG['password']}".encode("utf-8")).hexdigest()

    all_message = "confirm_share" + cipher_username + pwd
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = config.GLOBAL_CONFIG['shared_key'].encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()

    data = {
        "action": "confirm_share",
        "username": cipher_username,
        "auth": pwd,
        "hmac": hmac_result
    }
    
    response = requests.post(f"{base_url}/files/confirm_share", json=data).json()
    
    if response["status"] == "success":
        print("File share confirmed successfully.")
    else:
        print(f"Share confirmation failed: {response.get('file', 'Unknown error')}")