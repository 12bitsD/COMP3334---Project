from flask import Blueprint, request, jsonify
from models import Message, User
from app import db
from auth import token_required
from datetime import datetime
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
import base64

messages_bp = Blueprint('messages', __name__)

def verify_signature(message_hash, signature, public_key):
    try:
        key = RSA.import_key(public_key)
        h = SHA256.new(message_hash.encode())
        pkcs1_15.new(key).verify(h, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False

def decrypt_message(encrypted_content, private_key):
    try:
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        decrypted_content = cipher.decrypt(base64.b64decode(encrypted_content))
        return decrypted_content.decode()
    except Exception as e:
        return None

@messages_bp.route('/send', methods=['POST'])
@token_required
def send_message(current_user):
    data = request.get_json()
    
    if not data or not all(k in data for k in ['receiver_id', 'encrypted_content', 'message_hash', 'signature']):
        return jsonify({'message': '缺少必要的消息信息'}), 400
        
    receiver = User.query.filter_by(user_id=data['receiver_id']).first()
    if not receiver:
        return jsonify({'message': '接收者不存在'}), 404
        
    # 验证消息签名
    if not verify_signature(data['message_hash'], data['signature'], current_user.public_key):
        return jsonify({'message': '消息签名验证失败'}), 400
    
    new_message = Message(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        encrypted_content=data['encrypted_content'],
        message_hash=data['message_hash'],
        signature=data['signature']
    )
    
    try:
        db.session.add(new_message)
        db.session.commit()
        return jsonify({
            'message': '消息发送成功',
            'message_id': new_message.id,
            'timestamp': new_message.timestamp.isoformat()
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': '消息发送失败'}), 500

@messages_bp.route('/inbox', methods=['GET'])
@token_required
def get_inbox(current_user):
    try:
        messages = Message.query.filter_by(
            receiver_id=current_user.id
        ).order_by(Message.timestamp.desc()).all()
        
        return jsonify({
            'messages': [{
                'id': msg.id,
                'sender_id': User.query.get(msg.sender_id).user_id,
                'encrypted_content': msg.encrypted_content,
                'message_hash': msg.message_hash,
                'signature': msg.signature,
                'timestamp': msg.timestamp.isoformat(),
                'status': msg.status
            } for msg in messages]
        }), 200
    except Exception as e:
        return jsonify({'message': '获取收件箱失败'}), 500

@messages_bp.route('/outbox', methods=['GET'])
@token_required
def get_outbox(current_user):
    try:
        messages = Message.query.filter_by(
            sender_id=current_user.id
        ).order_by(Message.timestamp.desc()).all()
        
        return jsonify({
            'messages': [{
                'id': msg.id,
                'receiver_id': User.query.get(msg.receiver_id).user_id,
                'encrypted_content': msg.encrypted_content,
                'message_hash': msg.message_hash,
                'signature': msg.signature,
                'timestamp': msg.timestamp.isoformat(),
                'status': msg.status
            } for msg in messages]
        }), 200
    except Exception as e:
        return jsonify({'message': '获取发件箱失败'}), 500

@messages_bp.route('/message/<int:message_id>/status', methods=['PUT'])
@token_required
def update_message_status(current_user, message_id):
    data = request.get_json()
    if not data or 'status' not in data:
        return jsonify({'message': '缺少状态信息'}), 400
        
    message = Message.query.get(message_id)
    if not message:
        return jsonify({'message': '消息不存在'}), 404
        
    if message.receiver_id != current_user.id:
        return jsonify({'message': '无权更新此消息状态'}), 403
        
    try:
        message.status = data['status']
        db.session.commit()
        return jsonify({'message': '消息状态更新成功', 'status': message.status}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': '状态更新失败'}), 500