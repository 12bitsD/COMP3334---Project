import hashlib
import json
import sys
import requests
import config

headers = {"Content-Type": "application/json"}
base_url = config.GLOBAL_CONFIG['base_url']

def reset_password(args):
    suffix = "/auth/change_password"
    user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
    pwd = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest()
    new_password = hashlib.sha256(f"{args.new_password}".encode("utf-8")).hexdigest()
    data = {'user_id': user_id,'current_password_hash':pwd,'new_password_hash':new_password}
    response_raw = requests.post(base_url + suffix, data=json.dumps(data), headers=headers)
    response = response_raw.json()
    print(response['message'])


def reset(args):
    suffix = "/auth/reset"
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


def register(args):
    suffix = "/auth/register"
    if args.password != args.confirm_password:
        print("password mismatch, please try again")
    else:
        print(f"Registering user: {args.username}")
        pwd = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest()
        user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
        data = {"user_id": user_id, "password_hash": pwd, "public_key": config.GLOBAL_CONFIG['public_key'], "email": args.email,}
        changeStatus(data,args.username,args.password,suffix)

def exit():
    sys.exit()

def login(args):
    suffix = "/auth/login"
    print(f"{args.username} logging...")
    pwd = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest()
    user_id = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
    data = {"user_id": user_id, "password_hash": pwd}
    changeStatus(data,args.username,args.password,suffix)

def log(args):
    print(f"Fetching logs for user: {args.username}")