# Authentication Blueprint for handling user registration, login, and logout
from flask import Blueprint, request, jsonify
from models import User
from app import db
from datetime import datetime, timedelta
import os

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    """Handle user registration request.
    Expects JSON with user_id field.
    """
    data = request.get_json()
    
    if not data or not data.get('user_id'):
        return jsonify({'status': 'error', 'message': 'Missing required registration information'}), 400
        
    if User.query.filter_by(user_id=data['user_id']).first():
        return jsonify({'status': 'error', 'message': 'User already exists'}), 409
        
    new_user = User(
        user_id=data['user_id']
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Registration successful', 'data': {'user_id': new_user.user_id}}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Registration failed'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """Handle user login request.
    Expects JSON with user_id field.
    Updates last login timestamp.
    """
    data = request.get_json()
    
    if not data or not data.get('user_id'):
        return jsonify({'status': 'error', 'message': 'Missing login information'}), 400
        
    user = User.query.filter_by(user_id=data['user_id']).first()
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
    
    try:
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'data': {'user_id': user.user_id}
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Login failed'}), 500

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """Handle user logout request.
    Expects JSON with user_id field.
    """
    data = request.get_json()
    if not data or not data.get('user_id'):
        return jsonify({'status': 'error', 'message': 'Missing user information'}), 400
        
    user = User.query.filter_by(user_id=data['user_id']).first()
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
    return jsonify({'status': 'success', 'message': 'Logout successful'}), 200