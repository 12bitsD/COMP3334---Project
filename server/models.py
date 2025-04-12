from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, UTC

# 创建一个SQLAlchemy实例，但不初始化它
db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(64), unique=True, nullable=False)  # 客户端生成的用户ID哈希值
    password_hash = db.Column(db.String(128), nullable=False)  # 客户端生成的密码哈希值
    public_key = db.Column(db.LargeBinary, nullable=False)  # 用户的公钥
    email = db.Column(db.String(120), unique=True, nullable=True)  # 用户邮箱（可选）
    otp = db.Column(db.String(16), nullable=True)  # 临时OTP码
    otp_expires_at = db.Column(db.DateTime, nullable=True)  # OTP过期时间
    last_login = db.Column(db.DateTime)
    files = db.relationship('File', backref='owner', lazy=True)

class File(db.Model):
    """文件模型，存储用户上传的加密文件"""
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)  # 加密的文件名
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # 文件所有者
    encrypted_content = db.Column(db.Text, nullable=False)  # 加密的文件内容

class FileShare(db.Model):
    """文件共享模型，存储文件共享关系"""
    __tablename__ = 'file_shares'
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # 共享发起人
    shared_with_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # 共享接收人
    encrypted_content = db.Column(db.Text, nullable=True)  # 接收者可以解密的内容
    __table_args__ = (db.UniqueConstraint('file_id', 'shared_with_id', name='unique_file_user_share'),)

class AuditLog(db.Model):
    """审计日志模型，记录用户操作"""
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(64), nullable=False)
    resource_type = db.Column(db.String(64), nullable=True)
    resource_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(UTC))

class UserSession(db.Model):
    """用户会话模型，存储用户登录会话信息"""
    __tablename__ = 'user_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(128), unique=True, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)  # 支持IPv6地址
    user_agent = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, default=False)
    last_activity = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
