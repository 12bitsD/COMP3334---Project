import hashlib
import json
import sys
import requests
import config
from CryptographyController import *
import base64
import os

headers = {"Content-Type": "application/json"}
base_url = config.GLOBAL_CONFIG['base_url']

def init(password):
    #print('success')
    # 使用绝对路径
    keypair_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keypair.json")
    try:
        with open(keypair_path, 'r') as f:
            keypair = json.load(f)
            #print('success')
            if keypair['metadata'] is None:
                dk_salt = os.urandom(16)
                dk = derive_key(password, dk_salt)
                print(dk)
                #print('success')
                private_key_pem, public_key_pem = generate_keys()
                private_key = load_private_key(private_key_pem)
                ciphertext,nonce,enc_salt = encrypt(dk, base64.b64encode(private_key_pem).decode('utf-8'))
                public_key = load_public_key(public_key_pem)
                keypair = {
                    'metadata': "Secure",
                    'private_key': base64.b64encode(ciphertext).decode('utf-8'),
                    'public_key': base64.b64encode(public_key_pem).decode('utf-8'),
                    "dk_salt": base64.b64encode(dk_salt).decode('utf-8'),
                    'enc_salt': base64.b64encode(enc_salt).decode('utf-8'),
                    "nonce": base64.b64encode(nonce).decode('utf-8'),
                }
                print(keypair)
                with open(keypair_path, 'w', encoding = 'utf-8') as file:
                    json.dump(keypair,file, indent=4)
            else:
                dk_salt = base64.b64decode(keypair['dk_salt'])
                dk = derive_key(password, dk_salt)
                print(dk)
                print(keypair)
                private_key = load_private_key(
                    base64.b64decode(
                        decrypt(
                            dk,
                            base64.b64decode(keypair['private_key']),
                            base64.b64decode(keypair['nonce'])
                        ),
                    )
                )
                public_key = load_public_key(base64.b64decode(keypair['public_key']))
    except FileNotFoundError:
        # 文件不存在，创建包含空元数据的文件
        with open(keypair_path, 'w', encoding = 'utf-8') as file:
            json.dump({"metadata": None}, file, indent=4)
        
        # 使用新文件重新运行init
        return init(password)
    
    config.GLOBAL_CONFIG['private_key'] = private_key
    config.GLOBAL_CONFIG['public_key'] = public_key


def reset_password(args):
    suffix = "/change_password"
    user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
    pwd = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest()
    new_password = hashlib.sha256(f"{args.new_password}".encode("utf-8")).hexdigest()
    signature_raw = sign(user_id.encode("utf-8") + pwd.encode("utf-8") + new_password.encode("utf-8"))
    signature = base64.b64encode(signature_raw).decode('utf-8')
    data = {'user_id': user_id,'current_password_hash':pwd,'new_password_hash':new_password,'signature':signature}
    response_raw = requests.post(base_url + suffix, data=data, headers=headers)
    response = response_raw.json()
    print(response['message'])


def reset(args):   #extra revised needed
    suffix = "/otp/request"
    user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
    data = {"user_id": user_id}
    response_raw = requests.post(base_url + suffix, headers=headers, data=data) #request otp
    response = response_raw.json()
    if response["status"] == "success":
        otp = input("Input the otp sent to your email.")
        new_password = hashlib.sha256(f"{args.new_password}".encode("utf-8")).hexdigest()
        suffix = "/reset" #authenticate otp
        signature = sign(user_id + new_password).decode("utf-8")
        data = {'user_id': user_id,'password': otp,'new_password_hash':new_password,'signature':signature}
        response_raw = requests.post(base_url + suffix, headers=headers, data=data)
        response = response_raw.json()
        if response["status"] == "success":
            print(response["file"])
    else:
        print("Unknown error.")

def changeStatus(data,username,password,suffix):
    response_raw = requests.post(base_url + suffix, headers=headers, json=data)
    response = response_raw.json()
    if response["status"] == "success":
        config.GLOBAL_CONFIG['username'] = username
        config.GLOBAL_CONFIG['password'] = password
        config.GLOBAL_CONFIG['loginStatus'] = True
    print(response["message"])
    return response['status'] == 'success' , response


def register(args):
    suffix = "/auth/register"
    status = False
    if args.password != args.confirm_password:
        print("password mismatch, please try again")
    else:
        print(f"Registering user: {args.username}")
        init(args.password)
        pwd = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest()
        user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
        
        
        data = {"user_id": user_id,
                "password_hash": pwd,
                "public_key": 111,
                "email": args.email}
        status,response = changeStatus(data,args.username,args.password,suffix)


def exit():
    sys.exit()

def login(args):
    suffix = "/login"
    print(f"{args.username} logging...")
    pwd = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest()
    user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
    signature_raw = sign(user_id.encode("utf-8") + pwd.encode("utf-8"))
    signature = base64.b64encode(signature_raw).decode('utf-8')
    data = {"user_id": user_id, "password_hash": pwd,"signature":signature}
    status,response = changeStatus(data,args.username,args.password,suffix)
    if status and response['admin']:
        config.GLOBAL_CONFIG['admin'] = True


def log(args):
    if not config.GLOBAL_CONFIG['admin']:
        print("No access privileged")
        return
    print(f"Fetching logs for user: {args.username}")
    user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
    suffix = "/logs?user_id="+user_id
    response_raw = requests.get(base_url + suffix, headers=headers)
    response = response_raw.json()
    if response["status"] == "success":
        print(response["logs"])
    else:
        print(response["file"])