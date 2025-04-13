import hashlib
import json
import pwd
import sys
import requests

import config
from CryptographyController import *
import base64

headers = {"Content-Type": "application/json"}
base_url = config.GLOBAL_CONFIG['base_url']

def init(user_id,password):
    with open("keypair.json",'r') as f:
        keypair = json.load(f)
        found = False
        ctr = 0
        if keypair[0]['metadata'] == "Secure":
            for item in keypair[1:]:
                ctr+=1
                if item['user_id'] == user_id:
                    found = True
                    dk_salt = base64.b64decode(item['dk_salt'])
                    dk = derive_key(password, dk_salt)
                    private_key_pem = base64.b64decode(
                        decrypt(
                            dk,
                            base64.b64decode(item['private_key']),
                            base64.b64decode(item['nonce'])
                        ),
                    )
                    public_key_pem = base64.b64decode(item['public_key'])
                    private_key = load_private_key(private_key_pem)
                    public_key = load_public_key(public_key_pem)
        if (keypair[0]['metadata'] is None) or (found == False):
            dk_salt = os.urandom(16)
            dk = derive_key(password, dk_salt)
            keypair[0]['metadata'] = "Secure"
            private_key_pem, public_key_pem = generate_keys()
            private_key = load_private_key(private_key_pem)
            ciphertext,nonce,enc_salt = encrypt(dk, base64.b64encode(private_key_pem).decode('utf-8'))
            public_key = load_public_key(public_key_pem)
            data = {
                'user_id': user_id,
                'private_key': base64.b64encode(ciphertext).decode('utf-8'),
                'public_key': base64.b64encode(public_key_pem).decode('utf-8'),
                "dk_salt": base64.b64encode(dk_salt).decode('utf-8'),
                'enc_salt': base64.b64encode(enc_salt).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
            }
            keypair.append(data)
            with open('keypair.json', 'w', encoding = 'utf-8') as file:
                json.dump(keypair,file, indent=4)
    config.GLOBAL_CONFIG['private_key'] = private_key
    config.GLOBAL_CONFIG['public_key'] = public_key
    config.GLOBAL_CONFIG['public_key_pem'] = public_key_pem
    config.GLOBAL_CONFIG['private_key_pem'] = private_key_pem

def reset_local(user_id,password,newpassword):
    with open("keypair.json",'r') as f:
        keypair = json.load(f)
    ctr = 0
    for item in keypair[1:]:
        if item['user_id'] == user_id:
            ctr += 1
            dk_new_salt = os.urandom(16)
            dk_salt = base64.b64decode(item['dk_salt'])
            dk_dec = derive_key(password, dk_salt)
            dk_enc = derive_key(newpassword, dk_new_salt)
            private_key_pem = base64.b64decode(
                decrypt(
                    dk_dec,
                    base64.b64decode(item['private_key']),
                    base64.b64decode(item['nonce'])
                ),
            )
            public_key_pem = base64.b64decode(item['public_key'])
            private_key = load_private_key(private_key_pem)
            public_key = load_public_key(public_key_pem)
            ciphertext, nonce, enc_salt = encrypt(dk_enc, base64.b64encode(private_key_pem).decode('utf-8'))
            data = {
                'user_id': user_id,
                'private_key': base64.b64encode(ciphertext).decode('utf-8'),
                'public_key': base64.b64encode(public_key_pem).decode('utf-8'),
                "dk_salt": base64.b64encode(dk_new_salt).decode('utf-8'),
                'enc_salt': base64.b64encode(enc_salt).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
            }
            keypair.pop(ctr)
            keypair.append(data)
            with open('keypair.json', 'w', encoding='utf-8') as file:
                json.dump(keypair, file, indent=4)
                config.GLOBAL_CONFIG['private_key'] = private_key
                config.GLOBAL_CONFIG['public_key'] = public_key
                config.GLOBAL_CONFIG['public_key_pem'] = public_key_pem
                config.GLOBAL_CONFIG['private_key_pem'] = private_key_pem


def reset_password(args):
    if not config.GLOBAL_CONFIG['loginStatus']:
        print("Please login first!")
        return
    suffix = "/auth/reset"
    #print("password:"+args.password)
    #print("username:"+args.username)
    user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
    pwd = hashlib.sha256(f"{args.new_password}".encode("utf-8")).hexdigest()
    new_password = hashlib.sha256(f"{args.new_password}".encode("utf-8")).hexdigest()
    init(args.username,args.password)
    signature_raw = sign(user_id.encode("utf-8") + pwd.encode("utf-8"))
    signature = base64.b64encode(signature_raw).decode('utf-8')
    data = {'user_id': user_id,'current_password_hash':pwd,'new_password_hash':new_password,"signature":signature}
    response_raw = requests.post(base_url + suffix, json=data, headers=headers)
    response = response_raw.json()
    if response['status'] == 'success':
        reset_local(user_id,args.password,args.new_password)
        print("successfully reset password")
    print(response['file']+"\nPlease login again.")
    config.GLOBAL_CONFIG['loginStatus'] = False
    config.GLOBAL_CONFIG['username'] = ""
    config.GLOBAL_CONFIG['password'] = ""


def reset(args):   #extra revised needed
    suffix = "/auth/otp/request"
    user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
    data = {"user_id": user_id}
    response_raw = requests.post(base_url + suffix, headers=headers, json=data) #request otp
    response = response_raw.json()
    if response["status"] == "success":
        otp = input("Input the otp sent to your email:")
        new_password = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest()
        suffix = "/auth/reset" #authenticate otp
        #signature = sign(user_id + new_password).decode("utf-8")
        data = {'user_id': user_id,'password': otp,'new_password_hash':new_password}
        response_raw_2 = requests.post(base_url + suffix, headers=headers, json=data)
        response_2 = response_raw_2.json()
        if response_2["status"] == "success":
            reset_local(user_id,args.password,args.new_password)
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
    print(response["file"])
    return response['status'] == 'success' , response


def register(args):
    suffix = "/auth/register"
    status = False
    if args.password != args.confirm_password:
        print("password mismatch, please try again")
    else:
        print(f"Registering user: {args.username}")
        pwd = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest()
        user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
        init(user_id, args.password)
        signature_raw = sign(user_id.encode("utf-8") + pwd.encode("utf-8"))
        signature = base64.b64encode(signature_raw).decode('utf-8')
        #print(type(config.GLOBAL_CONFIG['public_key']))
        data = {"user_id": user_id,
                "password_hash": pwd,
                "public_key": base64.b64encode(config.GLOBAL_CONFIG['public_key_pem']).decode('utf-8'),
                "email": args.email,
                "signature":signature}
        status,response = changeStatus(data,args.username,args.password,suffix)


def exit():
    sys.exit()

def login(args):
    suffix = "/auth/login"
    print(f"{args.username} logging...")
    pwd = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest()
    user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
    init(user_id, args.password)
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
    suffix = "/auth/logs?user_id="+user_id
    response_raw = requests.get(base_url + suffix, headers=headers)
    response = response_raw.json()
    if response["status"] == "success":
        print(response["logs"])
    else:
        print(response["file"])