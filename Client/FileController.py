from LoginController import *
import hmac
from CryptographyController import *
from LoginController import *
import hmac
from CryptographyController import *
import config
from cryptography.hazmat.primitives import serialization

headers = {"Content-Type": "application/json"}
base_url = config.GLOBAL_CONFIG['base_url']

def header_enc(filename):
    cipher_username = encrypt_with_public_key(config.GLOBAL_CONFIG['username'], config.GLOBAL_CONFIG['public_key']).hex()
    cipher_filename = encrypt_with_public_key(filename, config.GLOBAL_CONFIG['public_key']).hex()
    pwd = hashlib.sha256(f"{config.GLOBAL_CONFIG['password']}".encode("utf-8")).hexdigest()
    return cipher_username, cipher_filename, pwd

def upload_starter(args):
    filename=args.filename
    upload(filename)

def upload(filename):
    suffix = "/files/upload"
    public_key=config.GLOBAL_CONFIG['public_key']
    private_key=config.GLOBAL_CONFIG['private_key']
    username = config.GLOBAL_CONFIG['username']
    username_hashed = hashlib.sha256(f"{username}".encode("utf-8")).hexdigest()

    #global shared_key, username, password,public_key,shared_key
    with open(filename, "r", encoding="utf-8") as f:
        plaintext = f.read()
    ciphertext = encrypt_with_public_key(plaintext, public_key).hex()
    cipher_username, cipher_filename, pwd = header_enc(filename)

    all_message = "upload" + username_hashed + cipher_filename + ciphertext
    message_bytes = all_message.encode('utf-8')

    signature_raw = sign(message_bytes)
    signature = base64.b64encode(signature_raw).decode('utf-8')

    #print("cipher_username 类型是：", type(cipher_username))
    data = {"action": "upload",
            "filename": cipher_filename,
            "username": username_hashed,
            "content": ciphertext,
            "sign": signature
            }
    print("filename")
    response_raw = requests.post(base_url + suffix, json=data, headers=headers)
    response = response_raw.json()
    print(response["status"])
    if response["status"] == "success":
        print(f"File uploaded successfully. File ID: {response.get('file_id', 'unknown')}")
    else:
        print(f"Upload failed: {response.get('file', 'Unknown error')}")

def download_strater(args):
    filename=args.filename
    download(filename)
def download(filename):
    suffix = "/files/download"
    username = config.GLOBAL_CONFIG['username']
    username_hashed = hashlib.sha256(f"{username}".encode("utf-8")).hexdigest()


    cipher_username, cipher_filename, pwd = header_enc(filename)
    all_message = "download" + username_hashed + cipher_filename
    message_bytes = all_message.encode('utf-8')

    signature_raw = sign(message_bytes)
    signature = base64.b64encode(signature_raw).decode('utf-8')

    data_send = {
        "action": "download",
        "filename": cipher_filename,
        "username": username_hashed,
        "sign":signature
    }
    response_raw = requests.post(base_url + suffix, json=data_send, headers=headers)
    response = response_raw.json()
    print(response.get('file', response.get('message', 'No message')))
    #提取里面的 content
    encrypted_content = bytes.fromhex(response["content"])
    decrypted_text = decrypt_with_private_key(encrypted_content, config.GLOBAL_CONFIG['private_key'])
    print(decrypted_text)

def delete_starter(args):
    filename=args.filename
    delete(filename)

def delete(filename):
    suffix = "/files/delete"
    #global username, password, public_key, shared_key
    cipher_username, cipher_filename, pwd = header_enc(filename)
    username = config.GLOBAL_CONFIG['username']
    username_hashed = hashlib.sha256(f"{username}".encode("utf-8")).hexdigest()

    all_message = "delete" + username_hashed + cipher_filename
    message_bytes = all_message.encode('utf-8')

    signature_raw = sign(message_bytes)
    signature = base64.b64encode(signature_raw).decode('utf-8')

    data_send = {
        "action": "delete",
        "filename": cipher_filename,
        "username": username_hashed,
        "sign":signature
    }
    response_raw = requests.post(base_url + suffix, json=data_send, headers=headers)
    response = response_raw.json()
    if response["status"] == "success":
        print("File deleted successfully.")
    else:
        print(f"Delete failed: {response.get('file', 'Unknown error')}")

def edit_starter(args):
    filename=args.filename
    updated_content=args.updated_content
    edit(filename,updated_content)

def edit(filename,updated_content):
    suffix = "/files/update"
    public_key=config.GLOBAL_CONFIG['public_key']
    #global username, password, public_key, shared_key
    cipher_username, cipher_filename, pwd = header_enc(filename)
    ciphertext = encrypt_with_public_key(updated_content, public_key).hex()
    username = config.GLOBAL_CONFIG['username']
    username_hashed=hashlib.sha256(f"{username}".encode("utf-8")).hexdigest()


    all_message = "update" + username_hashed + cipher_filename + ciphertext
    message_bytes = all_message.encode('utf-8')
    signature_raw = sign(message_bytes)
    signature = base64.b64encode(signature_raw).decode('utf-8')

    data_send = {
        "action": "update",
        "filename": cipher_filename,
        "username": username_hashed,
        "content": ciphertext,
        "sign":signature,
    }
    response_raw = requests.post(base_url + suffix, json=data_send, headers=headers)
    response = response_raw.json()
    if response["status"] == "success":
        print("File updated successfully.")
    else:
        print(f"Update failed: {response.get('file', 'Unknown error')}")

def share_starter(args):
    filename=args.filename
    to_user=args.to_user
    share(filename,to_user)

def share(filename, to_user):
    suffix = "/files/ask_share"
    username = config.GLOBAL_CONFIG['username']

    cipher_username, cipher_filename, pwd = header_enc(filename)
    to_user_hashed=hashlib.sha256(f"{to_user}".encode("utf-8")).hexdigest()
    username_hashed=hashlib.sha256(f"{username}".encode("utf-8")).hexdigest()


    all_message = "share1" + username_hashed + cipher_filename +to_user_hashed
    message_bytes = all_message.encode('utf-8')

    signature_raw = sign(message_bytes)
    signature = base64.b64encode(signature_raw).decode('utf-8')

    data_send = {
        "action": "ask_share",
        "filename": cipher_filename,
        "username": username_hashed,
        "sign":signature,
        "to_user": to_user_hashed
    }
    response_raw = requests.post(base_url + suffix, json=data_send, headers=headers)
    response = response_raw.json()
    content=response.get('encrypted_content', response.get('content', ''))
    ano_public_key_pem=response.get('target_public_key', response.get('public_key', ''))
    ano_public_key=serialization.load_pem_public_key(ano_public_key_pem)
    cipher_content=encrypt_with_public_key(content, ano_public_key).hex()
    confirm_share(filename,to_user,cipher_content,ano_public_key)

def confirm_share(filename,to_user,cipher_content,ano_public_key):

    suffix = "/files/confirm_share"
    username = config.GLOBAL_CONFIG['username']
    private_key=config.GLOBAL_CONFIG['private_key']

    cipher_username, cipher_filename, pwd = header_enc(filename)
    to_user_hashed = hashlib.sha256(f"{to_user}".encode("utf-8")).hexdigest()
    username_hashed = hashlib.sha256(f"{username}".encode("utf-8")).hexdigest()

    all_message2 = "share2" + username_hashed + cipher_filename + to_user_hashed
    message_bytes2 = all_message2.encode('utf-8')

    signature_raw = sign(message_bytes2)
    signature = base64.b64encode(signature_raw).decode('utf-8')

    content=decrypt_with_private_key(cipher_content,private_key)
    ano_cipher_content=encrypt_with_public_key(content,ano_public_key)

    data_send_2={
        "action":"share content",
        "content": ano_cipher_content,
        "filename":cipher_filename,
        "username": username_hashed,
        "to_user": to_user_hashed,
        "sign":signature
    }
    response_raw = requests.post(base_url + suffix, json=data_send_2, headers=headers)
    response = response_raw.json()
    if response["status"] == "success":
        print("File shared successfully.")
    else:
        print(f"Share failed: {response.get('file', 'Unknown error')}")