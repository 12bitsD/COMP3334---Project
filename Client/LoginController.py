import hashlib
import json
import sys
import requests
import config

username = config.GLOBAL_CONFIG['username']
password = config.GLOBAL_CONFIG['password']
loginStatus = config.GLOBAL_CONFIG['loginStatus']

base_url = "http://localhost:5000"

def sendAndRev(data):
    action = data.get("action", "")
    
    if action == "register":
        response = requests.post(f"{base_url}/auth/register", json={
            "user_id": data["username"], 
            "password_hash": data["password"],
            "public_key": config.GLOBAL_CONFIG.get('public_key', ""),
            "email": data.get("email", "")
        })
    elif action == "reset":
        if "password" in data:
            response = requests.post(f"{base_url}/auth/reset_password", json={
                "user_id": data["username"],
                "new_password_hash": data["password"]
            })
        else:
            response = requests.post(f"{base_url}/auth/request_reset", json={
                "user_id": data["username"]
            })
    elif action == "AuthenticateOTP":
        response = requests.post(f"{base_url}/auth/verify_otp", json={
            "otp": data["otp"]
        })
    elif action in ["upload", "ask_share", "confirm_share"]:
        response = requests.post(f"{base_url}/files/{action}", json=data)
    elif action == "download":
        username = data["username"]
        auth = data["auth"]
        filename = data["filename"]
        response = requests.get(f"{base_url}/files/download", params={
            "username": username,
            "auth": auth,
            "filename": filename,
            "hmac": data.get("hmac", "")
        })
    elif action == "delete":
        username = data["username"]
        auth = data["auth"]
        filename = data["filename"]
        response = requests.delete(f"{base_url}/files/delete", params={
            "username": username,
            "auth": auth,
            "filename": filename,
            "hmac": data.get("hmac", "")
        })
    else:
        # Default fallback
        response = requests.post(f"{base_url}/api", json=data)
    
    return response.json()


def help(admin=False):
    print("register <username> <password> <email_address> <confirm_password> (register a user)")
    print("login <username> <password> (login with username and password)")
    print("reset <username> <password> (reset the password of a user)")
    print(
        "upload <from_file_path> <to_file_path> (upload file from local to system)")  # must log all the action(login, logout, upload, delete, share)
    print("download <from_file_path> <to_file_path> (download file from system to local)")
    print("delete <file_path> (delete the file in the system)")
    print("share <file_path> <shared_user> (share the specific file with specific user)")
    print("edit <file_path> (editing files in the system)")
    print("exit (exit the program)")
    if admin:
        print("log <username> (print all the log of a specific user)")


def reset(args):
    data = {"action": "reset", "username": args.username}
    response = sendAndRev(data)
    if response["status"] == "pending":
        otp = input("input the otp sent to your email.")
        data = {"action": "AuthenticateOTP", "otp": otp}
        response = sendAndRev(data)
        if response["status"] == "success":
            ctr = 0
            newpwd = input("input the new password.")
            cfmpwd = input("confirm the new password.")
            while newpwd != cfmpwd and ctr < 4:
                print("New passwords do not match.")
                newpwd = input("input the new password.")
                cfmpwd = input("confirm the new password.")
                ctr += 1
            if (ctr < 4):
                pwd = hashlib.sha256(newpwd.encode()).hexdigest()
                data = {"action": "reset", "username": args.username, "password": pwd}
                response = sendAndRev(data)
                if response["status"] == "success":
                    print("Password has been reset.")
            else:
                print("Too many attempts, try again.")
        else:
            print("OTP authentication unsuccessful.")
    else:
        print("Unknown error.")


def register(args):
    if args.password != args.confirm_password:
        print("password mismatch, please try again")
    else:
        print(f"Registering user: {args.username}......")
        pwd = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest()
        usrnm = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
        data = {"action": "register", "username": usrnm, "password": pwd, "email": args.email}
        response = sendAndRev(data)
        if response["status"] == "success":
            print("user registered")
        else:
            print(f"{response['file']}")

def exit():
    sys.exit()

def login(args):
    print("logging...")
    pwd = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest()
    usrnm = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
    data = {
        "user_id": usrnm,
        "password_hash": pwd
    }
    response = requests.post(f"{base_url}/auth/login", json=data).json()
    if response["status"] == "success":
        print("user logged in")
        global username
        username = args.username
        global password
        password = args.password
        global loginStatus
        loginStatus = True
        return True
    return False


def log(args):
    print(f"Fetching logs for user: {args.username}")
    username_hash = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
    response = requests.get(f"{base_url}/utilities/logs", params={"user_id": username_hash}).json()
    if response["status"] == "success":
        logs = response.get("logs", [])
        for log in logs:
            print(log)
    else:
        print(f"Error fetching logs: {response.get('file', 'Unknown error')}")