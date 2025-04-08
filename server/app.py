from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 初始化Flask应用
app = Flask(__name__)

# 配置数据库
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_message.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')

# 初始化数据库
db = SQLAlchemy(app)

# 配置请求限制器
limiter = Limiter(
key_func=get_remote_address,
app=app,
default_limits=["200 per day", "50 per hour"]
)

# 全局错误处理
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'status': 'error',
        'message': '请求过于频繁，请稍后再试'
    }), 429

@app.errorhandler(404)
def not_found(e):
    return jsonify({
        'status': 'error',
        'message': '请求的资源不存在'
    }), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({
        'status': 'error',
        'message': '服务器内部错误'
    }), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)