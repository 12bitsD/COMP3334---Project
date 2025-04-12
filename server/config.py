import os
from datetime import timedelta

class Config:
    # 基础配置
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    DEBUG = True
    TESTING = False
    
    # 数据库配置
    SQLALCHEMY_DATABASE_URI = 'sqlite:///secure_message.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    

    
    # 安全配置
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    
    # 速率限制配置
    RATELIMIT_DEFAULT = "200 per day"
    RATELIMIT_STORAGE_URL = "memory://"
    
    # 加密配置
    MINIMUM_KEY_LENGTH = 2048  # RSA密钥最小长度
    
    # 共享密钥配置（用于HMAC验证）
    SHARED_KEY = os.getenv('SHARED_KEY', 'your-shared-key-for-hmac')
    
    # 邮件配置
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.163.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 465))
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'bits12@163.com')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'LUCrPibST8FDEYgL')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'bits12@163.com')
    
    # OTP配置
    OTP_VALIDITY_PERIOD = 300  # OTP有效期（秒）
    OTP_LENGTH = 6  # OTP长度
