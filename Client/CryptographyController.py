import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import modes, algorithms, Cipher
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import config


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def enc(data):
    iv = os.urandom(16)
    key = config.GLOBAL_CONFIG['key']
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # 创建加密器
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # 加密数据
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return (encrypted_data, salt, iv)


def generate_keys():
    """生成 RSA 公私钥对并返回 PEM 格式的 bytes"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem

def load_public_key(public_key_pem: bytes):
    """从 bytes 加载 RSA 公钥"""
    return serialization.load_pem_public_key(public_key_pem)

def load_private_key(private_key_pem: bytes):
    """从 bytes 加载 RSA 私钥"""
    return serialization.load_pem_private_key(private_key_pem, password=None)

def encrypt_with_public_key(plaintext: str, public_key) -> bytes:
    """使用 RSA 公钥加密字符串"""
    ciphertext = public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_with_private_key(ciphertext: bytes, private_key) -> str:
    """使用 RSA 私钥解密"""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')


def get_shared_key(data_receive, private_key):
    encrypted_content = bytes.fromhex(data_receive["cipher_shared_key"])
    decrypted_shared_key = decrypt_with_private_key(encrypted_content, private_key)
    shared_key = decrypted_shared_key
    return shared_key

