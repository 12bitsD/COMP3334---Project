from FileController import *
from LoginController import *
import argparse
import shlex
import config
import traceback

def help(args):
    print("register <username> <password> <confirm_password> <email_address> (register a user)")
    print("login <username> <password> (login with username and password)")
    print("reset <username> <password> (reset the password of a user)")
    print("reset_password <username> <password> <confirm_password> (reset the password of a user when knowing your origin password)>")
    print("upload <from_file_path> <to_file_path> (upload file from local to system)")  # must log all the action(login, logout, upload, delete, share)
    print("download <from_file_path> <to_file_path> (download file from system to local)")
    print("delete <file_path> (delete the file in the system)")
    print("share <file_path> <shared_user> (share the specific file with specific user)")
    print("edit <file_path> (editing files in the system)")
    print("exit (exit the program)")
    if config.GLOBAL_CONFIG['admin']:
        print("log <username> (print all the log of a specific user)")

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

    reset_password_parser = subparsers.add_parser("reset_password")
    reset_password_parser.add_argument("username")
    reset_password_parser.add_argument("password")
    reset_password_parser.add_argument("new_password")
    reset_password_parser.set_defaults(func=reset_password)

    register_parser = subparsers.add_parser("register")
    register_parser.add_argument("username")
    register_parser.add_argument("password")
    register_parser.add_argument("confirm_password")
    register_parser.add_argument("email")
    register_parser.set_defaults(func=register)

    login_parser = subparsers.add_parser("login")
    login_parser.add_argument("username")
    login_parser.add_argument("password")
    login_parser.set_defaults(func=login)

    upload_parser = subparsers.add_parser("upload")
    upload_parser.add_argument("filename")
    upload_parser.set_defaults(func=upload_starter)

    download_parser = subparsers.add_parser("download")
    download_parser.add_argument("filename")
    download_parser.set_defaults(func=download_strater)

    delete_parser = subparsers.add_parser("delete")
    delete_parser.add_argument("filename")
    delete_parser.set_defaults(func=delete_starter)

    share_parser = subparsers.add_parser("share")
    share_parser.add_argument("filename")
    share_parser.add_argument("to_user")
    share_parser.set_defaults(func=share_starter)

    edit_parser = subparsers.add_parser("edit")
    edit_parser.add_argument("filename")
    edit_parser.add_argument("updated_content")
    edit_parser.set_defaults(func=edit_starter)

    log_parser = subparsers.add_parser("log")
    log_parser.add_argument("username")
    log_parser.set_defaults(func=log)

    help_parser = subparsers.add_parser("help")
    help_parser.set_defaults(func=help)

    while True:
        try:
            if not config.GLOBAL_CONFIG['loginStatus']:
                #print(f"{config.GLOBAL_CONFIG['username']},{config.GLOBAL_CONFIG['password']},{config.GLOBAL_CONFIG['loginStatus']}")
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
            traceback.print_exc()
            print(f"Error: {e}")

if __name__ == '__main__':
    cmd()