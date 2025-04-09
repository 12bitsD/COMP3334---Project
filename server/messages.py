from flask import Blueprint, request, jsonify
from models import Message, User, MessagePermission
from app import db
from auth import token_required
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
@token_required
def send_message(current_user):
    """Send an encrypted message to another user.
    Args:
        current_user: The authenticated user sending the message
    Returns:
        JSON response with message status and details
    """
    data = request.get_json()
    
    if not data or not all(k in data for k in ['receiver_id', 'encrypted_content']):
        return jsonify({'message': 'Missing required message information'}), 400
        
    receiver = User.query.filter_by(user_id=data['receiver_id']).first()
    if not receiver:
        return jsonify({'message': 'Receiver not found'}), 404
    
    new_message = Message(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        encrypted_content=data['encrypted_content']
    )
    
    try:
        # 创建消息
        db.session.add(new_message)
        db.session.commit()
        return jsonify({
            'message': 'Message sent successfully',
            'message_id': new_message.id,
            'timestamp': new_message.timestamp.isoformat()
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to send message'}), 500

@messages_bp.route('/inbox', methods=['GET'])
@token_required
def get_inbox(current_user):
    """Retrieve all messages in the user's inbox including those with granted permissions.
    Args:
        current_user: The authenticated user requesting their inbox
    Returns:
        JSON response with list of messages
    """
    try:
        # 获取用户作为接收者的消息
        received_messages = Message.query.filter_by(receiver_id=current_user.id)
        
        # 获取用户有权限访问的其他消息
        permitted_messages = Message.query.join(MessagePermission).filter(
            MessagePermission.user_id == current_user.id,
            MessagePermission.permission_type.in_(['read', 'write', 'admin'])
        )
        
        # 合并两种消息并按时间排序
        messages = received_messages.union(permitted_messages).order_by(Message.timestamp.desc()).all()
        
        return jsonify({
            'messages': [{
                'id': msg.id,
                'sender_id': User.query.get(msg.sender_id).user_id,
                'encrypted_content': msg.encrypted_content,
                'timestamp': msg.timestamp.isoformat()
            } for msg in messages]
        }), 200
    except Exception as e:
        return jsonify({'message': 'Failed to get inbox'}), 500

@messages_bp.route('/outbox', methods=['GET'])
@token_required
def get_outbox(current_user):
    """Retrieve all messages sent by the user.
    Args:
        current_user: The authenticated user requesting their outbox
    Returns:
        JSON response with list of sent messages
    """
    try:
        messages = Message.query.filter_by(
            sender_id=current_user.id
        ).order_by(Message.timestamp.desc()).all()
        
        return jsonify({
            'messages': [{
                'id': msg.id,
                'receiver_id': User.query.get(msg.receiver_id).user_id,
                'encrypted_content': msg.encrypted_content,
                'timestamp': msg.timestamp.isoformat()
            } for msg in messages]
        }), 200
    except Exception as e:
        return jsonify({'message': 'Failed to get outbox'}), 500

@messages_bp.route('/message/<int:message_id>/permission', methods=['POST'])
@token_required
def grant_permission(current_user, message_id):
    """Grant message access permission to another user.
    Args:
        current_user: The authenticated user granting permission
        message_id: The ID of the message to grant permission for
    Returns:
        JSON response with permission status
    """
    data = request.get_json()
    if not data or not all(k in data for k in ['user_id', 'permission_type']):
        return jsonify({'message': 'Missing required permission information'}), 400
    
    # 检查授权者是否有管理权限
    has_permission, error_msg = check_message_permission(current_user.id, message_id, 'admin')
    if not has_permission:
        return jsonify({'message': error_msg}), 403
    
    target_user = User.query.filter_by(user_id=data['user_id']).first()
    if not target_user:
        return jsonify({'message': 'Target user not found'}), 404
    
    try:
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
                granted_by=current_user.id
            )
            db.session.add(new_permission)
        
        db.session.commit()
        return jsonify({'message': 'Permission granted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to grant permission'}), 500

@messages_bp.route('/message/<int:message_id>/permission', methods=['DELETE'])
@token_required
def revoke_permission(current_user, message_id):
    """Revoke message access permission from a user.
    Args:
        current_user: The authenticated user revoking permission
        message_id: The ID of the message to revoke permission for
    Returns:
        JSON response with permission status
    """
    data = request.get_json()
    if not data or 'user_id' not in data:
        return jsonify({'message': 'Missing user information'}), 400
    
    # 检查撤销者是否有管理权限
    has_permission, error_msg = check_message_permission(current_user.id, message_id, 'admin')
    if not has_permission:
        return jsonify({'message': error_msg}), 403
    
    target_user = User.query.filter_by(user_id=data['user_id']).first()
    if not target_user:
        return jsonify({'message': 'Target user not found'}), 404
    
    try:
        permission = MessagePermission.query.filter_by(
            message_id=message_id,
            user_id=target_user.id
        ).first()
        
        if permission:
            db.session.delete(permission)
            db.session.commit()
            return jsonify({'message': 'Permission revoked successfully'}), 200
        else:
            return jsonify({'message': 'Permission record not found'}), 404
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to revoke permission'}), 500