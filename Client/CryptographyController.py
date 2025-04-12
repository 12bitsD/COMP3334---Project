import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import config

def derive_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """将用户密码转换为 32 字节的 AES-256 密钥"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 需要 32 字节密钥
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))

# 2. 加密数据（AES-GCM）
def encrypt(key: bytes, plaintext: str) -> tuple[bytes, bytes, bytes]:
    """加密字符串，返回 (密文, nonce, salt)"""
    salt = os.urandom(16)  # 随机盐（存储它以便解密）
    nonce = os.urandom(12)  # AES-GCM 需要 12 字节的 nonce
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return ciphertext, nonce, salt

# 3. 解密数据（AES-GCM）
def decrypt(key: bytes, ciphertext: bytes, nonce: bytes) -> str:
    """解密字节数据为字符串"""
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")

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

def sign(message):
    private_key = config.GLOBAL_CONFIG['private_key']
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature
