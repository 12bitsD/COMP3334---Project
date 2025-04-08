from flask import Blueprint, request, jsonify
from models import User
from app import db
from datetime import datetime, timedelta
import os

auth_bp = Blueprint('auth', __name__)

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
    
    try:
        # 更新用户最后登录时间
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': '登录成功',
            'user_id': user.user_id
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': '登录失败'}), 500

@auth_bp.route('/logout', methods=['POST'])
def logout():
    data = request.get_json()
    if not data or not data.get('user_id'):
        return jsonify({'message': '缺少用户信息'}), 400
        
    user = User.query.filter_by(user_id=data['user_id']).first()
    if not user:
        return jsonify({'message': '用户不存在'}), 404
        
    return jsonify({'message': '登出成功'}), 200