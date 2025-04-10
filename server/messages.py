from flask import Blueprint, request, jsonify
from models import Message, User, MessagePermission
from app import db
from datetime import datetime
import base64

messages_bp = Blueprint('messages', __name__)

def check_message_permission(user_id, message_id, required_permission='read'):
    """Check if a user has the specified permission for a message.
    Args:
        user_id: The ID of the user requesting permission
        message_id: The ID of the message to check
        required_permission: The type of permission to check (read/write/admin)
    Returns:
        tuple: (bool, str) - (has permission, error message if any)
    """
    message = Message.query.get(message_id)
    if not message:
        return False, 'Message not found'
    
    # Message sender and receiver automatically have all permissions
    if message.sender_id == user_id or message.receiver_id == user_id:
        return True, ''
        
    # Check if user has required permission
    permission = MessagePermission.query.filter_by(
        message_id=message_id,
        user_id=user_id
    ).first()
    
    if not permission:
        return False, 'No permission to access this message'
        
    if required_permission == 'read' and permission.permission_type in ['read', 'write', 'admin']:
        return True, ''
    elif required_permission == 'write' and permission.permission_type in ['write', 'admin']:
        return True, ''
    elif required_permission == 'admin' and permission.permission_type == 'admin':
        return True, ''
        
    return False, 'Insufficient permission'

@messages_bp.route('/send', methods=['POST'])
def send_message():
    """Send an encrypted message to another user.
    Expects JSON with user_id, receiver_id, and encrypted_content.
    Returns:
        JSON response with message status and details
    """
    data = request.get_json()
    
    # 从请求中获取发送者ID和接收者ID
    sender = User.query.filter_by(user_id=data['user_id']).first()
    if not sender:
        return jsonify({'message': 'Sender not found', 'status': 'error'}), 404
        
    receiver = User.query.filter_by(user_id=data['receiver_id']).first()
    if not receiver:
        return jsonify({'message': 'Receiver not found', 'status': 'error'}), 404
    
    new_message = Message(
        sender_id=sender.id,
        receiver_id=receiver.id,
        encrypted_content=data['encrypted_content']
    )
    
    # 创建消息
    db.session.add(new_message)
    db.session.commit()
    return jsonify({
        'message': 'Message sent successfully',
        'message_id': new_message.id,
        'timestamp': new_message.timestamp.isoformat(),
        'status': 'success'
    }), 201

@messages_bp.route('/inbox', methods=['GET'])
def get_inbox():
    """Retrieve all messages in the user's inbox including those with granted permissions.
    Expects query parameter user_id.
    Returns:
        JSON response with list of messages
    """
    # 从请求参数获取用户ID
    user_id = request.args.get('user_id')
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({'message': 'User not found', 'status': 'error'}), 404
        
    # 获取用户作为接收者的消息
    received_messages = Message.query.filter_by(receiver_id=user.id)
    
    # 获取用户有权限访问的其他消息
    permitted_messages = Message.query.join(MessagePermission).filter(
        MessagePermission.user_id == user.id,
        MessagePermission.permission_type.in_(['read', 'write', 'admin'])
    )
    
    # 合并两种消息并按时间排序
    messages = received_messages.union(permitted_messages).order_by(Message.timestamp.desc()).all()
    
    return jsonify({
        'messages': [{
            'id': msg.id,
            'sender_id': User.query.get(msg.sender_id).user_id if User.query.get(msg.sender_id) else 'Unknown',
            'encrypted_content': msg.encrypted_content,
            'timestamp': msg.timestamp.isoformat()
        } for msg in messages],
        'status': 'success'
    }), 200

@messages_bp.route('/outbox', methods=['GET'])
def get_outbox():
    """Retrieve all messages sent by the user.
    Expects query parameter user_id.
    Returns:
        JSON response with list of sent messages
    """
    # 从请求参数获取用户ID
    user_id = request.args.get('user_id')
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({'message': 'User not found', 'status': 'error'}), 404
        
    messages = Message.query.filter_by(
        sender_id=user.id
    ).order_by(Message.timestamp.desc()).all()
    
    return jsonify({
        'messages': [{
            'id': msg.id,
            'receiver_id': User.query.get(msg.receiver_id).user_id if User.query.get(msg.receiver_id) else 'Unknown',
            'encrypted_content': msg.encrypted_content,
            'timestamp': msg.timestamp.isoformat()
        } for msg in messages],
        'status': 'success'
    }), 200

@messages_bp.route('/message/<int:message_id>/permission', methods=['POST'])
def grant_permission(message_id):
    """Grant message access permission to another user.
    Expects JSON with user_id (grantor) and target_user_id (grantee) and permission_type.
    Returns:
        JSON response with permission status
    """
    data = request.get_json()
    
    # 从请求中获取授权用户ID
    user_id = data['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({'message': 'User not found', 'status': 'error'}), 404
    
    # 检查授权者是否有管理权限
    has_permission, error_msg = check_message_permission(user.id, message_id, 'admin')
    if not has_permission:
        return jsonify({'message': error_msg, 'status': 'error'}), 403
    
    target_user = User.query.filter_by(user_id=data['target_user_id']).first()
    if not target_user:
        return jsonify({'message': 'Target user not found', 'status': 'error'}), 404
    
    # 检查是否已存在权限记录
    existing_permission = MessagePermission.query.filter_by(
        message_id=message_id,
        user_id=target_user.id
    ).first()
    
    if existing_permission:
        existing_permission.permission_type = data['permission_type']
    else:
        new_permission = MessagePermission(
            message_id=message_id,
            user_id=target_user.id,
            permission_type=data['permission_type'],
            granted_by=user.id
        )
        db.session.add(new_permission)
    
    db.session.commit()
    return jsonify({'message': 'Permission granted successfully', 'status': 'success'}), 200

@messages_bp.route('/message/<int:message_id>/permission', methods=['DELETE'])
def revoke_permission(message_id):
    """Revoke message access permission from a user.
    Expects JSON with user_id (revoker) and target_user_id (revokee).
    Returns:
        JSON response with permission status
    """
    data = request.get_json()
    
    # 从请求中获取撤销权限的用户ID
    user_id = data['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({'message': 'User not found', 'status': 'error'}), 404
    
    # 检查撤销者是否有管理权限
    has_permission, error_msg = check_message_permission(user.id, message_id, 'admin')
    if not has_permission:
        return jsonify({'message': error_msg, 'status': 'error'}), 403
    
    target_user = User.query.filter_by(user_id=data['target_user_id']).first()
    if not target_user:
        return jsonify({'message': 'Target user not found', 'status': 'error'}), 404
    
    permission = MessagePermission.query.filter_by(
        message_id=message_id,
        user_id=target_user.id
    ).first()
    
    if permission:
        db.session.delete(permission)
        db.session.commit()
        return jsonify({'message': 'Permission revoked successfully', 'status': 'success'}), 200
    else:
        return jsonify({'message': 'Permission record not found', 'status': 'error'}), 404