from LoginController import *
import hmac
from CryptographyController import *
import config

def header_enc(filename):
    cipher_username = encrypt_with_public_key(config.GLOBAL_CONFIG['username'], config.GLOBAL_CONFIG['public_key']).hex()
    cipher_filename = encrypt_with_public_key(filename, config.GLOBAL_CONFIG['public_key']).hex()
    pwd = hashlib.sha256(f"{config.GLOBAL_CONFIG['username'] + config.GLOBAL_CONFIG['password']}".encode("utf-8")).hexdigest()
    return cipher_username, cipher_filename, pwd

def upload(filename):
    #global shared_key, username, password,public_key,shared_key
    with open("content.txt", "r", encoding="utf-8") as f:
        plaintext = f.read()
    ciphertext = encrypt_with_public_key(plaintext, public_key).hex()
    cipher_username, cipher_filename, pwd = header_enc(filename)

    all_message = "action" + cipher_username + cipher_filename + ciphertext + pwd
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = shared_key.encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()

    #print("cipher_username 类型是：", type(cipher_username))
    data = {"action": "upload",
            "filename": cipher_filename,
            "username": cipher_username,
            "content": ciphertext,
            "auth": pwd,
            "hmac": hmac_result
            }
    confirm = sendAndRev(data)


def download(filename):
    #global username, password, public_key, shared_key
    cipher_username, cipher_filename, pwd = header_enc(filename)
    all_message = "download" + cipher_username + cipher_filename + pwd
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = shared_key.encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()

    data_send = {
        "action": "download",
        "filename": cipher_filename,
        "username": cipher_username,
        "auth": pwd,
        "hmac": hmac_result
    }
    data_receive = sendAndRev(data_send)
    #提取里面的 content
    encrypted_content = bytes.fromhex(data_receive["content"])
    decrypted_text = decrypt_with_private_key(encrypted_content, config.GLOBAL_CONFIG['private_key'])
    print(decrypted_text)


def delete(filename):
    #global username, password, public_key, shared_key
    cipher_username, cipher_filename, pwd = header_enc(filename)

    all_message = "delete" + cipher_username + cipher_filename + pwd
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = shared_key.encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()

    data_send = {
        "action": "delete",
        "filename": cipher_filename,
        "username": cipher_username,
        "auth": pwd,
        "hmac": hmac_result
    }
    confirm = sendAndRev(data_send)


def edit(filename,updated_content):
    #global username, password, public_key, shared_key
    cipher_username, cipher_filename, pwd = header_enc(filename)
    ciphertext = encrypt_with_public_key(updated_content, public_key).hex()

    all_message = "update" + cipher_username + cipher_filename + ciphertext + pwd
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = shared_key.encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()

    data_send = {
        "action": "update",
        "filename": cipher_filename,
        "username": cipher_username,
        "content": ciphertext,
        "auth": pwd,
        "hmac": hmac_result
    }
    confirm = sendAndRev(data_send)


def ask_share(filename, to_user):
    #global username, password, public_key, shared_key
    cipher_username, cipher_filename, pwd = header_enc(filename)
    cipher_to_user = encrypt_with_public_key(to_user, config.GLOBAL_CONFIG['public_key']).hex()

    all_message = "ask_share" + cipher_username + cipher_filename + pwd + to_user
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = config.GLOBAL_CONFIG['shared_key'].encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()

    data_send = {
        "action": "ask_share",
        "filename": cipher_filename,
        "username": cipher_username,
        "auth": pwd,
        "to_user": cipher_to_user,
        "hmac": hmac_result
    }
    confirm = sendAndRev(data_send)


def confirm_share():
    #global username, password, public_key, shared_key
    cipher_username = encrypt_with_public_key(username, config.GLOBAL_CONFIG['public_key']).hex()
    pwd = hashlib.sha256(f"{username + password}".encode("utf-8")).hexdigest()

    all_message = "confirm_share" + cipher_username + pwd
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = config.GLOBAL_CONFIG['shared_key'].encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()

    data_send = {
        "action": "confirm_share",
        "username": cipher_username,
        "auth": pwd,
        "hmac": hmac_result
    }
    confirm = sendAndRev(data_send)