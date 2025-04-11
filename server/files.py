from flask import Blueprint, request, jsonify, current_app
from models import User, File, FileShare
from run import db
from datetime import datetime, UTC
import hashlib
import hmac
import re
import os
import json
from auth import log_action

files_bp = Blueprint('files', __name__)

@files_bp.route('/upload', methods=['POST'])
def upload_file():
    """上传加密文件
    Expects JSON with:
        - user_id/username: 用户ID 
        - password_hash/auth: 密码哈希
        - filename: 加密的文件名
        - encrypted_content: 加密的文件内容
        - signature/hmac: 客户端签名
    """
    data = request.get_json()
    
    try:
        # 支持两种参数命名风格
        user_id = data.get('user_id') or data.get('username')
        if not user_id:
            return jsonify({
                'status': 'error',
                'message': 'Missing user_id/username parameter'
            }), 400
            
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
            
        # 检查文件名
        filename = data.get('filename')
        if not filename:
            return jsonify({
                'status': 'error',
                'message': 'Missing filename parameter'
            }), 400
            
        # 检查加密内容
        encrypted_content = data.get('encrypted_content')
        if not encrypted_content:
            return jsonify({
                'status': 'error',
                'message': 'Missing encrypted_content parameter'
            }), 400
            
        # 创建新文件
        new_file = File(
            filename=filename,
            owner_id=user.id,
            encrypted_content=encrypted_content
        )
        db.session.add(new_file)
        db.session.commit()
        
        # 记录文件上传操作
        log_action(
            user.id,
            'upload_file',
            resource_type='file',
            resource_id=new_file.id,
            details=f"Uploaded new file: {new_file.filename}"
        )
        
        return jsonify({
            'status': 'success',
            'file': 'File uploaded successfully',
            'file_id': new_file.id
        }), 201
            
    except Exception as e:
        db.session.rollback()
        print(f"文件上传错误: {str(e)}")  # 在服务器日志中记录详细错误
        return jsonify({
            'status': 'error',
            'message': f'Failed to upload file: {str(e)}'
        }), 500

@files_bp.route('/download', methods=['GET'])
def download_file_by_name():
    """根据文件名下载文件
    Expects query parameters:
        - username: 加密的用户名
        - auth: 密码哈希
        - filename: 加密的文件名
        - hmac: HMAC验证码
    """
    username = request.args.get('username')
    auth = request.args.get('auth')
    filename = request.args.get('filename')
    
    try:
        user = User.query.filter_by(user_id=username).first()
        F = File.query.filter_by(owner_id=user.id, filename=filename).first()
        
        # 记录文件下载操作
        log_action(
            user.id,
            'download_file',
            resource_type='file',
            resource_id=F.id,
            details=f"Downloaded file: {F.filename}"
        )
        
        # 返回文件内容
        return jsonify({
            'status': 'success',
            'encrypted_content': F.encrypted_content,
        }), 200
                
    except Exception as e:
        print(f"文件下载错误: {str(e)}")  # 在服务器日志中记录详细错误
        return jsonify({
            'status': 'error',
            'message': 'Failed to download file'
        }), 500

@files_bp.route('/ask_share', methods=['POST'])
def ask_share():
    """请求共享文件给指定用户
    Expects JSON with:
        - action: "ask_share"
        - username: 发起共享的用户名（加密）
        - auth: 密码哈希
        - filename: 要共享的文件名（加密）
        - to_user: 接收共享的用户名（加密）
        - hmac: HMAC验证码    
    Returns:
        - target_public_key: 目标用户的公钥，用于客户端加密
        - encrypted_content: 文件的加密内容
    """
    data = request.get_json()
    
    try:
        user = User.query.filter_by(user_id=data['username']).first()
        F = File.query.filter_by(owner_id=user.id, filename=data['filename']).first()
        
        # 寻找目标用户
        to_user_id = data['to_user']
        target_user = User.query.filter_by(user_id=to_user_id).first()
        
        # 记录共享请求
        log_action(
            user.id,
            'ask_share',
            resource_type='file',
            resource_id=F.id,
            details=f"Requested public key to share file: {F.filename} with user {target_user.user_id}"
        )
            
        # 返回目标用户的公钥、文件ID和加密内容
        return jsonify({
            'status': 'success',
            'file': 'Obtained target user public key',
            'target_public_key': target_user.public_key,
            'encrypted_content': F.encrypted_content
        }), 200
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': 'Failed to process share request'
        }), 500

@files_bp.route('/confirm_share', methods=['POST'])
def confirm_share():
    """确认并完成文件共享
    Expects JSON with:
        - action: "confirm_share"
        - username: 发起共享的用户名（加密）
        - auth: 密码哈希
        - filename: 要共享的文件名（加密）
        - to_user: 接收共享的用户名（加密）
        - encrypted_content: 为接收者加密的文件内容
        - hmac: HMAC验证码
    """
    data = request.get_json()
    
    try:
        user = User.query.filter_by(user_id=data['username']).first()
        file = File.query.filter_by(owner_id=user.id, filename=data['filename']).first()
        
        # 获取目标用户
        to_user_id = data['to_user']
        target_user = User.query.filter_by(user_id=to_user_id).first()
        
        # 检查目标用户是否已有同名文件
        target_file = File.query.filter_by(
            owner_id=target_user.id,
            filename=data['filename']
        ).first()
        
        if target_file:
            # 目标用户已有同名文件，添加后缀
            original_name = data['filename']
            new_filename = f"{original_name}_shared_from_{user.user_id}"
        else:
            new_filename = data['filename']
        
        # 创建新文件记录 - 不添加共享标记，视为目标用户的新文件
        new_file = File(
            owner_id=target_user.id,
            filename=new_filename,
            encrypted_content=data['encrypted_content']
        )
        
        db.session.add(new_file)
        db.session.commit()
        
        # 记录共享操作
        log_action(
            user.id,
            'share_file',
            resource_type='file',
            resource_id=file.id,
            details=f"Shared file '{file.filename}' with user {target_user.user_id}, created new file ID: {new_file.id}"
        )
        
        # 记录接收端操作
        log_action(
            target_user.id,
            'receive_file',
            resource_type='file',
            resource_id=new_file.id,
            details=f"Received file '{new_file.filename}' from user {user.user_id}"
        )
        
        # 返回成功响应
        return jsonify({
            'status': 'success',
            'file': 'File shared successfully',
            'new_file_id': new_file.id
        }), 200
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': 'Failed to complete file sharing'
        }), 500

@files_bp.route('/delete', methods=['DELETE'])
def delete_file_by_name():
    """根据文件名删除文件
    Expects query parameters:
        - username: 加密的用户名
        - auth: 密码哈希
        - filename: 加密的文件名
        - hmac: HMAC验证码
    """
    username = request.args.get('username')
    auth = request.args.get('auth')
    filename = request.args.get('filename')
    
    try:
        user = User.query.filter_by(user_id=username).first()
        F = File.query.filter_by(owner_id=user.id, filename=filename).first()
        
        # 记录文件名，用于日志
        file_name = F.filename
        
        # 删除文件及其共享记录
        db.session.delete(F)
        db.session.commit()
        
        # 记录删除操作
        log_action(
            user.id,
            'delete_file',
            details=f"Deleted file: {file_name}"
        )
        
        # 返回成功响应
        return jsonify({
            'status': 'success',
            'file': 'File deleted successfully'
        }), 200
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': 'Failed to delete file'
        }), 500

@files_bp.route('/update', methods=['PUT'])
def update_file():
    """更新文件内容
    Expects JSON with:
        - username: 发起更新的用户名（加密）
        - auth: 密码哈希
        - filename: 要更新的文件名（加密）
        - encrypted_content: 更新的加密文件内容
        - hmac: HMAC验证码
    """
    data = request.get_json()
    
    try:
        user = User.query.filter_by(user_id=data['username']).first()
        F = File.query.filter_by(owner_id=user.id, filename=data['filename']).first()
        
        # 更新文件内容，不使用updated_at字段
        F.encrypted_content = data['encrypted_content']
        db.session.commit()
        
        # 记录文件更新操作
        log_action(
            user.id,
            'update_file',
            resource_type='file',
            resource_id=F.id,
            details=f"Updated file: {F.filename}"
        )
        
        return jsonify({
            'status': 'success',
            'file': 'File updated successfully',
            'file_id': F.id
        }), 200
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': 'Failed to update file'
        }), 500
