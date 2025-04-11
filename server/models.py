from app import db
from datetime import datetime

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(256), unique=True, nullable=False)  # 客户端生成的用户ID哈希值
    password_hash = db.Column(db.String(256), nullable=False)  # 客户端生成的密码哈希值
    public_key = db.Column(db.Text, nullable=False)  # 用户的公钥
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    messages_sent = db.relationship('Message', backref='sender', lazy=True, foreign_keys='Message.sender_id')
    messages_received = db.relationship('Message', backref='receiver', lazy=True, foreign_keys='Message.receiver_id')

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)  # 加密后的消息内容
    # 消息发送的时间戳，默认为创建消息时的UTC时间
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(datetime.timezone.utc))
    # 添加与权限表的关系
    permissions = db.relationship('MessagePermission', backref='message', lazy=True)

class MessagePermission(db.Model):
    __tablename__ = 'message_permissions'
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    permission_type = db.Column(db.String(20), nullable=False)  # read, write, admin
    granted_at = db.Column(db.DateTime, default=lambda: datetime.now(datetime.timezone.utc))
    granted_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # 添加唯一约束确保每个用户对每个消息只有一个权限记录
    __table_args__ = (db.UniqueConstraint('message_id', 'user_id', name='unique_message_user_permission'),)
