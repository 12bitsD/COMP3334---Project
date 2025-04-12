from LoginController import *
import hmac
from CryptographyController import *
from LoginController import *
import hmac
from CryptographyController import *
import config

headers = {"Content-Type": "application/json"}
base_url = config.GLOBAL_CONFIG['base_url']

def header_enc(filename):
    cipher_username = encrypt_with_public_key(config.GLOBAL_CONFIG['username'], config.GLOBAL_CONFIG['public_key']).hex()
    cipher_filename = encrypt_with_public_key(filename, config.GLOBAL_CONFIG['public_key']).hex()
    pwd = hashlib.sha256(f"{config.GLOBAL_CONFIG['password']}".encode("utf-8")).hexdigest()
    return cipher_username, cipher_filename, pwd

def upload(filename):
    suffix = "/auth/message/send"
    public_key=config.GLOBAL_CONFIG['public_key']
    shared_key=config.GLOBAL_CONFIG['shared_key']
    username = config.GLOBAL_CONFIG['username']
    username_hashed = hashlib.sha256(f"{username}".encode("utf-8")).hexdigest()

    #global shared_key, username, password,public_key,shared_key
    with open("content.txt", "r", encoding="utf-8") as f:
        plaintext = f.read()
    ciphertext = encrypt_with_public_key(plaintext, public_key).hex()
    cipher_username, cipher_filename, pwd = header_enc(filename)

    all_message = "upload" + username_hashed + cipher_filename + ciphertext
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = shared_key.encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()


    signature=sign(b"upload")

    #print("cipher_username 类型是：", type(cipher_username))
    data = {"action": "upload",
            "filename": cipher_filename,
            "username": username_hashed,
            "content": ciphertext,
            "hmac": hmac_result,
            "sign": signature
            }
    response_raw = requests.post(base_url + suffix, data=json.dumps(data), headers=headers)
    response = response_raw.json()
    if response["status"] == "success":
        print(f"File uploaded successfully. File ID: {response.get('file_id', 'unknown')}")
    else:
        print(f"Upload failed: {response.get('file', 'Unknown error')}")

def download(filename):
    suffix = "/auth/message/send"
    shared_key=config.GLOBAL_CONFIG['shared_key']
    #global username, password, public_key, shared_key
    username = config.GLOBAL_CONFIG['username']
    username_hashed = hashlib.sha256(f"{username}".encode("utf-8")).hexdigest()


    cipher_username, cipher_filename, pwd = header_enc(filename)
    all_message = "download" + username_hashed + cipher_filename
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = shared_key.encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()

    signature=sign(b"download")

    data_send = {
        "action": "download",
        "filename": cipher_filename,
        "username": username_hashed,
        "sign":signature,
        "hmac": hmac_result
    }
    response_raw = requests.post(base_url + suffix, data=json.dumps(data_send), headers=headers)
    response = response_raw.json()
    print(response['message'])
    #提取里面的 content
    encrypted_content = bytes.fromhex(response["content"])
    decrypted_text = decrypt_with_private_key(encrypted_content, config.GLOBAL_CONFIG['private_key'])
    print(decrypted_text)


def delete(filename):
    suffix = "/auth/message/send"
    shared_key=config.GLOBAL_CONFIG['shared_key']
    #global username, password, public_key, shared_key
    cipher_username, cipher_filename, pwd = header_enc(filename)
    username = config.GLOBAL_CONFIG['username']
    username_hashed = hashlib.sha256(f"{username}".encode("utf-8")).hexdigest()

    all_message = "delete" + username_hashed + cipher_filename
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = shared_key.encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()

    signature = sign(b"delete")

    data_send = {
        "action": "delete",
        "filename": cipher_filename,
        "username": username_hashed,
        "sign":signature,
        "hmac": hmac_result
    }
    response_raw = requests.post(base_url + suffix, data=json.dumps(data_send), headers=headers)
    response = response_raw.json()
    if response["status"] == "success":
        print("File deleted successfully.")
    else:
        print(f"Delete failed: {response.get('file', 'Unknown error')}")


def edit(filename,updated_content):
    suffix = "/auth/message/send"
    shared_key = config.GLOBAL_CONFIG['shared_key']
    public_key=config.GLOBAL_CONFIG['public_key']
    #global username, password, public_key, shared_key
    cipher_username, cipher_filename, pwd = header_enc(filename)
    ciphertext = encrypt_with_public_key(updated_content, public_key).hex()
    username = config.GLOBAL_CONFIG['username']
    username_hashed=hashlib.sha256(f"{username}".encode("utf-8")).hexdigest()


    all_message = "update" + username_hashed + cipher_filename + ciphertext
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = shared_key.encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()
    signature = sign(b"download")

    data_send = {
        "action": "update",
        "filename": cipher_filename,
        "username": username_hashed,
        "content": ciphertext,
        "sign":signature,
        "hmac": hmac_result
    }
    response_raw = requests.post(base_url + suffix, data=json.dumps(data_send), headers=headers)
    response = response_raw.json()
    if response["status"] == "success":
        print("File updated successfully.")
    else:
        print(f"Update failed: {response.get('file', 'Unknown error')}")


def share(filename, to_user):
    suffix = "/auth/message/send"
    username = config.GLOBAL_CONFIG['username']

    cipher_username, cipher_filename, pwd = header_enc(filename)
    to_user_hashed=hashlib.sha256(f"{to_user}".encode("utf-8")).hexdigest()
    username_hashed=hashlib.sha256(f"{username}".encode("utf-8")).hexdigest()


    all_message = "share1" + username_hashed + cipher_filename +to_user_hashed
    message_bytes = all_message.encode('utf-8')
    shared_key_bytes = config.GLOBAL_CONFIG['shared_key'].encode('utf-8')
    h = hmac.new(shared_key_bytes, message_bytes, hashlib.sha256)
    hmac_result = h.hexdigest()

    signature = sign(b"share1")
    data_send = {
        "action": "ask_share",
        "filename": cipher_filename,
        "username": username_hashed,
        "sign":signature,
        "to_user": to_user_hashed,
        "hmac": hmac_result
    }
    response_raw = requests.post(base_url + suffix, data=json.dumps(data_send), headers=headers)
    response = response_raw.json()
    content=response['content']
    ano_public_key=response['public_key']
    cipher_content=encrypt_with_public_key(content, ano_public_key).hex()
    confirm_share(filename,to_user,cipher_content,ano_public_key)

def confirm_share(filename,to_user,cipher_content,ano_public_key):

    suffix = "/auth/message/send"
    username = config.GLOBAL_CONFIG['username']
    private_key=config.GLOBAL_CONFIG['private_key']

    cipher_username, cipher_filename, pwd = header_enc(filename)
    to_user_hashed = hashlib.sha256(f"{to_user}".encode("utf-8")).hexdigest()
    username_hashed = hashlib.sha256(f"{username}".encode("utf-8")).hexdigest()

    all_message2 = "share2" + username_hashed + cipher_filename + to_user_hashed
    message_bytes2 = all_message2.encode('utf-8')
    shared_key_bytes2 = config.GLOBAL_CONFIG['shared_key'].encode('utf-8')
    h2 = hmac.new(shared_key_bytes2, message_bytes2, hashlib.sha256)
    hmac_result2 = h2.hexdigest()
    signature2 = sign(b"share2")

    content=decrypt_with_private_key(cipher_content,private_key)
    ano_cipher_content=encrypt_with_public_key(content,ano_public_key)

    data_send_2={
        "action":"share content",
        "content": ano_cipher_content,
        "filename":cipher_filename,
        "username": username_hashed,
        "to_user": to_user_hashed,
        "hmac": hmac_result2,
        "sign":signature2
    }
    response_raw = requests.post(base_url + suffix, data=json.dumps(data_send_2), headers=headers)
    response = response_raw.json()
    if response["status"] == "success":
        print("File updated successfully.")
    else:
        print(f"Update failed: {response.get('file', 'Unknown error')}")