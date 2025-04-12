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