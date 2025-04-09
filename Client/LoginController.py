import hashlib
import json
import sys
import socket
import config

username = config.GLOBAL_CONFIG['username']
password = config.GLOBAL_CONFIG['password']
loginStatus = config.GLOBAL_CONFIG['loginStatus']

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1",8080))

def sendAndRev(data):
    client.sendall(json.dumps(data).encode())
    response = json.loads(client.recv(4096).decode())
    return response


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
    client.sendall(json.dumps(data).encode())
    response = json.loads(client.recv(1024).decode())
    if response["status"] == "pending":
        otp = input("input the otp sent to your email.")
        data = {"action": "AuthenticateOTP", "otp": otp}
        client.sendall(json.dumps(data).encode())
        response = json.loads(client.recv(1024).decode())
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
                client.sendall(json.dumps(data).encode())
                response = json.loads(client.recv(1024).decode())
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
        print(f"Registering user: {args.username}")
        pwd = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest()
        usrnm = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
        data = {"action": "register", "username": usrnm, "password": pwd, "email": args.email}
        client.sendall(json.dumps(data).encode())
        response = json.loads(client.recv(1024).decode())
        if response["status"] == "success":
            print("user registered")
        else:
            print(f"{response['message']}")

def exit():
    sys.exit()

def login(args):
    print("logging...")
    pwd = hashlib.sha256(f"{args.password}".encode("utf-8")).hexdigest()
    usrnm = hashlib.sha256(f"{args.username}".encode("utf-8")).hexdigest()
    data = {"action": "login", "username": usrnm, "password": pwd}
    client.sendall(json.dumps(data).encode())
    response = json.loads(client.recv(1024).decode())
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