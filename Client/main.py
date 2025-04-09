import os

from FileController import *
from LoginController import *
import argparse
import shlex
import socket
import threading
import config

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(("127.0.0.1",10022))
listener.listen(1)

def init():
    private_key_pem, public_key_pem = generate_keys()
    private_key = load_private_key(private_key_pem)
    public_key = load_public_key(public_key_pem)
    shared_key = get_shared_key(private_key, public_key)
    config.GLOBAL_CONFIG['private_key'] = private_key
    config.GLOBAL_CONFIG['public_key'] = public_key
    config.GLOBAL_CONFIG['shared_key'] = shared_key

def listen_client(listener_socket):
    client_listener, addr = listener_socket.accept()
    while True:
        data = client_listener.recv(4096)
        if not data:
            break
        action = json.loads(data)['action']
        if action == 'confirm_share':
            if not loginStatus:
                print("Did not login yet. Please login.")
            else:
                confirm_pwd = input("Input your password: ")
                if confirm_pwd == password:
                    confirm_share()

def save_keys():
    with open("./.env", "w") as f:
        f.write()

def cmd():
    parser = argparse.ArgumentParser(description="Command-line interface")
    subparsers = parser.add_subparsers(dest="command")

    exit_parser = subparsers.add_parser("exit")
    exit_parser.set_defaults(func=exit)

    reset_parser = subparsers.add_parser("reset")
    reset_parser.add_argument("username")
    reset_parser.add_argument("password")
    reset_parser.add_argument("confirm_password")
    reset_parser.set_defaults(func=reset)

    register_parser = subparsers.add_parser("register")
    register_parser.add_argument("username")
    register_parser.add_argument("password")
    register_parser.add_argument("email")
    register_parser.add_argument("confirm_password")
    register_parser.set_defaults(func=register)

    login_parser = subparsers.add_parser("login")
    login_parser.add_argument("username")
    login_parser.add_argument("password")
    login_parser.set_defaults(func=login)

    upload_parser = subparsers.add_parser("upload")
    upload_parser.add_argument("filename")
    upload_parser.set_defaults(func=upload)

    download_parser = subparsers.add_parser("download")
    download_parser.add_argument("filename")
    download_parser.set_defaults(func=download)

    delete_parser = subparsers.add_parser("delete")
    delete_parser.add_argument("filename")
    delete_parser.set_defaults(func=delete)

    share_parser = subparsers.add_parser("share")
    share_parser.add_argument("filename")
    share_parser.add_argument("to_user")
    share_parser.set_defaults(func=ask_share)

    edit_parser = subparsers.add_parser("edit")
    edit_parser.add_argument("filename")
    edit_parser.add_argument("updated_content")
    edit_parser.set_defaults(func=edit)

    log_parser = subparsers.add_parser("log")
    log_parser.add_argument("username")
    log_parser.set_defaults(func=log)

    help_parser = subparsers.add_parser("help")
    help_parser.set_defaults(func=help)
    threading.Thread(target=listen_client, args=(listener,)).start()
    while True:
        try:
            if not config.GLOBAL_CONFIG['loginStatus']:
                print(f"{config.GLOBAL_CONFIG['username']},{config.GLOBAL_CONFIG['password']},{config.GLOBAL_CONFIG['loginStatus']}")
                user_input = input("cmd> ")
            else:
                user_input = input(f"{config.GLOBAL_CONFIG['username']}> ")
            if user_input.lower() in ["exit", "quit"]:
                break
            args = parser.parse_args(shlex.split(user_input))
            if hasattr(args, "func"):
                args.func(args)
            else:
                parser.print_help()
        except SystemExit:
            print("Invalid command. Type 'help' for usage information.")
        except Exception as e:
            print(f"Error: {e}")


def main():
    init()
    cmd()

if __name__ == '__main__':
    main()