# Authentication Blueprint for handling user registration, login
from flask import Blueprint, request, jsonify, current_app
from models import User
from app import db
from datetime import datetime
import os

auth_bp = Blueprint('auth', __name__)

def verify_user_credentials(user_id, password_hash):
    """验证用户凭据
    Args:
        user_id: 用户ID
        password_hash: 密码哈希值
    Returns:
        tuple: (User对象, 错误消息, HTTP状态码)
        如果验证成功，返回 (User对象, None, None)
        如果验证失败，返回 (None, 错误消息, HTTP状态码)
    """
    # 检查用户是否存在
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return None, 'User not found', 404
    
    # 如果提供了密码哈希，检查是否匹配
    if password_hash is not None and user.password_hash != password_hash:
        return None, 'Invalid password', 401
    
    return user, None, None

@auth_bp.route('/register', methods=['POST'])
def register():
    """Handle user registration request.
    Expects JSON with user_id, password_hash, and public_key fields.
    """
    data = request.get_json()
    
    # 检查用户是否已存在
    if User.query.filter_by(user_id=data['user_id']).first():
        return jsonify({'status': 'success', 'message': 'User already exists'}), 200
        
    new_user = User(
        user_id=data['user_id'],
        password_hash=data['password_hash'],
        public_key=data['public_key']
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Registration successful', 'data': {'user_id': new_user.user_id}}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Registration failed: {str(e)}'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """Handle user login request.
    Expects JSON with user_id and password_hash fields.
    只验证用户ID和密码哈希是否在数据库中匹配.
    """
    data = request.get_json()
    
    # 直接查询用户ID和密码哈希是否匹配
    user = User.query.filter_by(
        user_id=data['user_id'], 
        password_hash=data['password_hash']
    ).first()
    
    # 检查用户是否存在
    user = User.query.filter_by(user_id=data['user_id']).first()
    if not user:
        return jsonify({
            'status': 'error',
            'message': 'User not found'
        }), 404
    
    # 检查密码哈希是否匹配
    if user.password_hash != data['password_hash']:
        return jsonify({
            'status': 'error',
            'message': 'Invalid password'
        }), 401
    
    # 登录成功
    return jsonify({
        'status': 'success',
        'message': 'Login successful',
        'data': {
            'user_id': user.user_id
        }
    }), 200

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
            'message': 'User not found'
        }), 404
    
    try:
        return jsonify({
            'status': 'success',
            'message': 'Public key retrieved successfully',
            'data': {
                'user_id': user.user_id,
                'public_key': user.public_key
            }
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to retrieve public key: {str(e)}'}), 500

@auth_bp.route('/change_password', methods=['POST'])
def change_password():
    """修改用户密码
    Expects JSON with user_id, current_password_hash, and new_password_hash fields.
    """
    data = request.get_json()
    # 验证用户凭据
    user, error_msg, status_code = verify_user_credentials(data['user_id'], data['current_password_hash'])
    if error_msg:
        return jsonify({
            'status': 'error',
            'message': error_msg
        }), status_code
    
    try:
        # 更新密码哈希
        user.password_hash = data['new_password_hash']
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Password changed successfully'
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Failed to change password: {str(e)}'
        }), 500