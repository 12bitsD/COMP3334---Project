import hashlib
import json
import sys
import requests
from crypto.SelfTest.Protocol.test_ecdh import private_key

import config
from CryptographyController import *

headers = {"Content-Type": "application/json"}
base_url = config.GLOBAL_CONFIG['base_url']

def init(password):
    dk_salt = os.urandom(16)
    dk = derive_key(password,dk_salt)
    with open("keypair.json",'r') as f:
        keypair = json.load(f)
        if keypair['metadata'] is None:
            salt = os.urandom(16)
            private_key_pem, public_key_pem = generate_keys()
            private_key = load_private_key(private_key_pem)
            ciphertext,nonce,enc_salt = encrypt(dk, private_key_pem.decode('utf-8'))
            public_key = load_public_key(public_key_pem)
            keypair = {
                'metadata': "Secure",
                'private_key': ciphertext.decode('utf-8'),
                'public_key': public_key_pem.decode('utf-8'),
                "dk_salt": dk_salt.decode('utf-8'),
                'enc_salt': enc_salt.decode('utf-8'),
                "nonce": nonce.decode('utf-8'),
            }
            with open('keypair.json', 'w', encoding = 'utf-8') as file:
                json.dump(keypair,file, indent=4)
        else:
            private_key = load_private_key(decrypt(keypair['private_key'],keypair['enc_salt'].encode('utf-8'),keypair['nonce'].encode('utf-8')).encode('utf-8'))
            public_key = load_public_key(keypair['public_key'].encode('utf-8'))
    config.GLOBAL_CONFIG['private_key'] = private_key
    config.GLOBAL_CONFIG['public_key'] = public_key


def reset_password(args):
    suffix = "/change_password"
    user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest().encode()
    pwd = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest().encode()
    new_password = hashlib.sha256(f"{args.new_password}".encode("utf-8")).hexdigest().encode()
    signature = sign(user_id + pwd + new_password).decode("utf-8")
    data = {'user_id': user_id,'current_password_hash':pwd,'new_password_hash':new_password,'signature':signature}
    response_raw = requests.post(base_url + suffix, data=json.dumps(data), headers=headers)
    response = response_raw.json()
    print(response['message'])


def reset(args):   #extra revised needed
    suffix = "/reset"
    user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
    data = {"user_id": user_id}
    response_raw = requests.post(base_url + suffix, headers=headers, data=json.dumps(data))
    response = response_raw.json()
    if response["status"] == "success":
        otp = input("Input the otp sent to your email.")
        data = {"otp": otp}
        suffix = "/auth/auth_otp"
        response_raw = requests.post(base_url + suffix, headers=headers, data=json.dumps(data))
        if response["status"] == "success":
            ctr = 0
            newpwd = input("input the new password.")
            cfmpwd = input("confirm the new password.")
            while newpwd != cfmpwd and ctr < 4:
                print("New passwords do not match.")
                newpwd = input("input the new password.")
                cfmpwd = input("confirm the new password.")
                ctr += 1
            if ctr < 4:
                pwd = hashlib.sha256(newpwd.encode()).hexdigest()
                suffix = "/auth/otp_change_password"
                data = {"user_id": user_id, "password": pwd}
                response_raw = requests.post(base_url + suffix, headers=headers, data=json.dumps(data))
                response = response_raw.json()
                if response["status"] == "success":
                    print("Password has been reset.")
            else:
                print("Too many attempts, try again.")
        else:
            print("OTP authentication unsuccessful.")
    else:
        print("Unknown error.")

def changeStatus(data,username,password,suffix):
    response_raw = requests.post(base_url + suffix, headers=headers, data=json.dumps(data))
    response = response_raw.json()
    if response["status"] == "success":
        config.GLOBAL_CONFIG['username'] = username
        config.GLOBAL_CONFIG['password'] = password
        config.GLOBAL_CONFIG['loginStatus'] = True
    print(response["message"])
    return response['status'] == 'success' , response


def register(args):
    suffix = "/register"
    status = False
    if args.password != args.confirm_password:
        print("password mismatch, please try again")
    else:
        print(f"Registering user: {args.username}")
        pwd = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest()
        user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
        signature = sign(user_id + pwd).decode("utf-8")
        data = {"user_id": user_id,
                "password_hash": pwd,
                "public_key": config.GLOBAL_CONFIG['public_key'],
                "email": args.email,
                "signature":signature}
        status,response = changeStatus(data,args.username,args.password,suffix)
    if status:
        init(args.password)


def exit():
    sys.exit()

def login(args):
    suffix = "/login"
    print(f"{args.username} logging...")
    pwd = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest()
    user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
    signature = sign(user_id + pwd).decode("utf-8")
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