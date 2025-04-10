from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import config
from auth import auth_bp
from messages import messages_bp
import os

def create_app(config_name='default'):
    app = Flask(__name__)
    
    # 加载配置
    app.config.from_object(config[config_name])
    
    # 初始化扩展
    db = SQLAlchemy(app)
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"]
    )
    
    # 注册蓝图
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(messages_bp, url_prefix='/messages')
    
    return app

if __name__ == '__main__':
    app = create_app('development')
    
    # 确保实例文件夹存在
    if not os.path.exists('instance'):
        os.makedirs('instance')
    
    # 创建数据库表
    with app.app_context():
        db = SQLAlchemy(app)
        
        # 检查是否需要迁移数据库（添加新列）
        from models import User
        from sqlalchemy import inspect
        
        inspector = inspect(db.engine)
        existing_columns = [column['name'] for column in inspector.get_columns('users')]
        
        # 确保数据库表结构是最新的
        db.create_all()
        
        # 如果表已存在但没有新添加的列，提示用户进行数据迁移
        if 'users' in inspector.get_table_names() and ('password_hash' not in existing_columns or 'public_key' not in existing_columns):
            print("警告: 用户表结构已更新，请备份数据并执行迁移!")
    
    # 启动应用
    app.run(host='0.0.0.0', port=5000)