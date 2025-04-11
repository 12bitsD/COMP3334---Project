# Authentication Blueprint for handling user registration, login
from flask import Blueprint, request, jsonify, current_app
from models import User, AuditLog, db, UserSession
from datetime import datetime, UTC, timedelta
import pyotp
import hashlib
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
from flask_mail import Message

auth_bp = Blueprint('auth', __name__)

def log_action(user_id, action, details=None, resource_type=None, resource_id=None, client_signature=None, operation_data=None):
    """Record user actions in the audit log
    Args:
        user_id: ID of the user performing the action
        action: Type of action being performed
        details: Additional details about the action
        resource_type: Type of resource being accessed (optional)
        resource_id: ID of the resource being accessed (optional)
        client_signature: Client signature for verification (optional)
        operation_data: Data related to the operation (optional)
    """
    try:
        log_entry = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            timestamp=datetime.now(UTC)
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        print(f"Failed to log action: {str(e)}")
        db.session.rollback()

def send_otp_email(email, otp_code):
    """发送OTP验证码邮件
    Args:
        email: 用户邮箱
        otp_code: OTP验证码
    Returns:
        bool: 发送成功返回True，否则返回False
    """
    try:
        msg = Message(
            subject='Your OTP Code for Secure Messaging App',
            recipients=[email],
            sender=current_app.config['MAIL_DEFAULT_SENDER']
        )
        
        msg.body = f"""Hey，
OTPCODE: {otp_code}

this code valid in {current_app.config.get('OTP_VALIDITY_PERIOD', 300) // 60}mins。
"""
        
        mail = current_app.extensions['mail']
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Failed to send OTP email: {str(e)}")
        return False

def generate_simple_otp():
    """生成简单的6位数字OTP验证码"""
    return ''.join(random.choices(string.digits, k=current_app.config.get('OTP_LENGTH', 6)))

def send_and_store_otp(user):
    """生成OTP，存储到用户记录，并发送到用户邮箱
    Args:
        user: 用户对象
    Returns:
        bool: 发送成功返回True，否则返回False
    """
    if not user.email:
        return False
        
    # 生成OTP
    otp = generate_simple_otp()
    
    # 存储OTP到用户记录，设置过期时间为60秒后
    user.otp = otp
    user.otp_expires_at = datetime.now(UTC) + timedelta(seconds=60)
    
    try:
        db.session.commit()
        
        # 发送OTP验证码邮件
        if send_otp_email(user.email, otp):
            return True
        else:
            # 发送失败，清除OTP
            user.otp = None
            user.otp_expires_at = None
            db.session.commit()
            return False
    except Exception as e:
        print(f"Failed to store OTP: {str(e)}")
        db.session.rollback()
        return False

def verify_user_credentials(user_id, password_hash):
    """验证用户凭据
    Args:
        user_id: 用户ID
        password_hash: 密码哈希值或OTP验证码
    Returns:
        tuple: (User对象, 错误消息, HTTP状态码)
        如果验证成功，返回 (User对象, None, None)
        如果验证失败，返回 (None, 错误消息, HTTP状态码)
    """
    # 检查用户是否存在
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return None, 'User not found', 404
    
    # 验证成功情况1: 密码匹配
    if(user.password_hash == password_hash): return user, None, None
    
    # 验证成功情况2: OTP匹配且未过期
    otp_correct = False
    if user.otp is not None and user.otp_expires_at is not None:
        if datetime.now(UTC) <= user.otp_expires_at and user.otp == password_hash:
            otp_correct = True
            # OTP验证成功后清除OTP
            user.otp = None
            user.otp_expires_at = None
            db.session.commit()
            return user, None, None
    
    # 验证失败
    return None, 'Invalid credentials', 401


def is_valid_email(email):
    """验证邮箱是否合法
    Args:
        email: 要验证的邮箱
    Returns:
        bool: 邮箱是否合法
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

@auth_bp.route('/register', methods=['POST'])
def register():
    """注册新用户
    Expects JSON with user_id, password_hash, and public_key fields.
    可选字段: email, signature, operation_data
    """
    data = request.get_json()

    
    # 检查用户是否已存在
    if User.query.filter_by(user_id=data['user_id']).first():
        return jsonify({
            'status': 'error',
            'file': 'User ID already exists'
        }), 400
    
    # 检查邮箱格式和唯一性
    if data.get('email'):
        if not is_valid_email(data.get('email')):
            return jsonify({
                'status': 'error',
                'file': 'Invalid email format'
            }), 400
            
        if User.query.filter_by(email=data.get('email')).first():
            return jsonify({
                'status': 'error',
                'file': 'Email already in use'
            }), 400
        
    try:
        # 创建新用户，email字段为可选
        new_user = User(
            user_id=data['user_id'],
            password_hash=data['password_hash'],
            public_key=data['public_key'],
            email=data.get('email'),  # 如果email不存在，默认为None
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # 记录用户注册
        # 由于是新用户注册，这里还不能验证签名，因为用户的公钥刚刚被添加
        log_action(
            new_user.id,
            'register',
            details=f"New user registered: {new_user.user_id}"
        )
        
        return jsonify({
            'status': 'success',
            'file': 'User registered successfully',
            'data': {
                'user_id': new_user.user_id,
                'email': new_user.email,
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'file': f'Failed to register user: {str(e)}'
        }), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """用户登录
    Expects JSON with user_id, password_hash fields.
    signature, operation_data
    """
    data = request.get_json()
    
    
    # 验证用户凭据
    user, error_msg, status_code = verify_user_credentials(
        data['user_id'], 
        data['password_hash']
    )

    if error_msg:
        return jsonify({
            'status': 'error',
            'file': error_msg
        }), status_code
    
    try:
        # 更新最后登录时间
        user.last_login = datetime.now(UTC)
        db.session.commit()
        
        # 记录用户登录
        log_action(
            user.id,
            'login',
            details=f"User logged in: {user.user_id}",
            client_signature=data['signature'],
            operation_data=None
        )
        return jsonify({
            'status': 'success',
            'file': 'User logged in successfully'
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'file': f'Failed to update login time: {str(e)}'
        }), 500
    

@auth_bp.route('/public_key', methods=['GET'])
def get_public_key():
    """获取用户的公钥
    Expects query parameter user_id
    """
    user_id = request.args.get('user_id')
    
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({
            'status': 'error',
            'file': 'User not found'
        }), 404
    
    try:
        # 记录公钥获取
        log_action(
            user.id,
            'get_public_key',
            details=f"Public key retrieved for user: {user.user_id}"
        )
        
        return jsonify({
            'status': 'success',
            'file': 'Public key retrieved successfully',
            'data': {
                'user_id': user.user_id,
                'public_key': user.public_key
            }
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'file': f'Failed to retrieve public key: {str(e)}'}), 500

@auth_bp.route('/reset', methods=['POST'])
def change_password():
    """修改用户密码
    Expects JSON with user_id, current_password_hash, and new_password_hash fields.
    可选字段: signature, operation_data
    """
    data = request.get_json()
    
    # 提取客户端签名
    client_signature = data.get('signature')
    
    # 验证用户凭据
    user, error_msg, status_code = verify_user_credentials(data['user_id'], data['current_password_hash'])
    if error_msg:
        return jsonify({
            'status': 'error',
            'file': error_msg
        }), status_code
    
    try:
        # 更新密码哈希
        user.password_hash = data['new_password_hash']
        db.session.commit()
        
        # 记录密码更改
        log_action(
            user.id,
            'change_password',
            details=f"Password changed for user: {user.user_id}",
            client_signature=client_signature,
            operation_data=None
        )
        
        return jsonify({
            'status': 'success',
            'file': 'Password changed successfully'
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'file': f'Failed to change password: {str(e)}'
        }), 500

@auth_bp.route('/logs', methods=['GET'])
def get_user_logs():
    """获取用户的操作日志
    Expects query parameters:
        - user_id: 用户ID
    """
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({
            'status': 'error',
            'file': 'Missing user_id parameter'
        }), 400
    
    # 检查用户是否存在
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({
            'status': 'error',
            'file': 'User not found'
        }), 404
    
    try:
        # 获取用户的日志
        logs = AuditLog.query.filter_by(user_id=user.id).order_by(AuditLog.timestamp.desc()).all()
        
        # 构建日志数据
        logs_data = [{
            'timestamp': log.timestamp.isoformat(),
            'action': log.action,
            'resource_type': log.resource_type,
            'resource_id': log.resource_id,
            'details': log.details
        } for log in logs]
        
        # 记录获取日志的操作
        log_action(
            user.id,
            'get_logs',
            details=f"Retrieved {len(logs)} log entries"
        )
        
        return jsonify({
            'status': 'success',
            'logs': logs_data
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'file': f'Failed to get logs: {str(e)}'
        }), 500

@auth_bp.route('/otp/request', methods=['POST'])
def request_otp():
    """请求发送OTP
    Expects JSON with user_id field.
    Returns:
        JSON response with OTP request status
    """
    data = request.get_json()
    
    if not data.get('user_id'):
        return jsonify({
            'status': 'error',
            'file': 'User ID is required'
        }), 400
    
    # 查找用户
    user = User.query.filter_by(user_id=data['user_id']).first()
    if not user:
        return jsonify({
            'status': 'error',
            'file': 'User not found'
        }), 404
    
    # 检查用户是否有邮箱
    if not user.email:
        return jsonify({
            'status': 'error',
            'file': 'User has no email address'
        }), 400
    
    try:
        # 使用新的OTP机制
        if send_and_store_otp(user):
            # 记录OTP请求
            log_action(
                user.id,
                'otp_requested',
                details=f"OTP requested for user: {user.user_id}"
            )
            
            return jsonify({
                'status': 'success',
                'file': 'OTP code sent to your email',
                'data': {
                    'user_id': user.user_id,
                    'email': user.email
                }
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'file': 'Failed to send OTP email'
            }), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'file': f'Failed to request OTP: {str(e)}'
        }), 500