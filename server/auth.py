from flask import Blueprint, request, jsonify
from models import User, Session
from app import db
from datetime import datetime, timedelta
import jwt
from functools import wraps
import os

auth_bp = Blueprint('auth', __name__)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': '缺少认证令牌'}), 401
        
        try:
            token = token.split(' ')[1]  # Bearer token
            session = Session.query.filter_by(token=token, is_active=True).first()
            if not session or session.expires_at < datetime.utcnow():
                return jsonify({'message': '无效或过期的令牌'}), 401
                
            current_user = User.query.get(session.user_id)
            return f(current_user, *args, **kwargs)
        except Exception as e:
            return jsonify({'message': '无效的认证令牌'}), 401
    return decorated

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not data.get('user_id'):
        return jsonify({'message': '缺少必要的注册信息'}), 400
        
    if User.query.filter_by(user_id=data['user_id']).first():
        return jsonify({'message': '用户已存在'}), 409
        
    new_user = User(
        user_id=data['user_id'],
        public_key=data.get('public_key')
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': '注册成功', 'user_id': new_user.user_id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': '注册失败'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('user_id'):
        return jsonify({'message': '缺少登录信息'}), 400
        
    user = User.query.filter_by(user_id=data['user_id']).first()
    if not user:
        return jsonify({'message': '用户不存在'}), 404
    
    # 生成访问令牌
    expires_at = datetime.utcnow() + timedelta(days=1)
    token = jwt.encode(
        {
            'user_id': user.id,
            'exp': expires_at
        },
        os.getenv('SECRET_KEY', 'your-secret-key-here'),
        algorithm='HS256'
    )
    
    # 创建新的会话
    session = Session(
        user_id=user.id,
        token=token,
        expires_at=expires_at
    )
    
    try:
        # 更新用户最后登录时间
        user.last_login = datetime.utcnow()
        db.session.add(session)
        db.session.commit()
        
        return jsonify({
            'message': '登录成功',
            'token': token,
            'expires_at': expires_at.isoformat()
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': '登录失败'}), 500

@auth_bp.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    token = request.headers.get('Authorization').split(' ')[1]
    session = Session.query.filter_by(token=token, is_active=True).first()
    
    if session:
        session.is_active = False
        try:
            db.session.commit()
            return jsonify({'message': '登出成功'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': '登出失败'}), 500
    
    return jsonify({'message': '无效的会话'}), 400