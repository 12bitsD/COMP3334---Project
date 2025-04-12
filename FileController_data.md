
__hmac用于完整性验证
sign用于签名__
# upload

data = {"action": "upload",  
        "filename": cipher_filename,  
        "username": username_hashed,  
        "content": ciphertext,  
        "hmac": hmac_result,  
        "sign": signature  
    }

signature=sign(b"upload")

hmac:"upload" + username_hashed + cipher_filename + ciphertext

### download

data_send = {  
    "action": "download",  
    "filename": cipher_filename,  
    "username": username_hashed,  
    "sign":signature,  
    "hmac": hmac_result  
}

signature=sign(b"download")

hmac:"download" + username_hashed + cipher_filename

需要获取的数据：
response[content]


### delete

data_send = {  
    "action": "delete",  
    "filename": cipher_filename,  
    "username": username_hashed,  
    "sign":signature,  
    "hmac": hmac_result  
}

signature = sign(b"delete")

hmac:"delete" + username_hashed + cipher_filename

### edit

data_send = {  
    "action": "update",  
    "filename": cipher_filename,  
    "username": username_hashed,  
    "content": ciphertext,  
    "sign":signature,  
    "hmac": hmac_result  
}
signature = sign(b"download")

hmac = "update" + username_hashed + cipher_filename + ciphertext

### share

share需要发两次数据
data_send = {  
    "action": "share_get_content_public_key",  
    "filename": cipher_filename,  
    "username": username_hashed,  
    "sign":signature,  
    "to_user": to_user_hashed,  
    "hmac": hmac_result  
}
signature = sign(b"share1")
hmac："share1" + username_hashed + cipher_filename +to_user_hashed

接受的数据：
response['content']
response['public_key"]<--这个public key是share目标的public key


data_send_2={  
    "action":"share content",  
    "content": cipher_content,  
    "filename":cipher_filename,  
    "username": username_hashed,  
    "to_user": to_user_hashed,  
    "hmac": hmac_result2,  
    "sign":signature2  
}

signature2 = sign(b"share2")
hmac："share2" + username_hashed + cipher_filename + to_user_hashed