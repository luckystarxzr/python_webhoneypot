import hashlib
import os
from datetime import timedelta

# 生成随机盐值
SALT = os.environ.get('WAF_SALT', 'luckystarxzr')

# 管理员账号配置
ADMIN_CONFIG = {
    'admin': {
        # 使用 SHA256 加密存储密码
        'password_hash': hashlib.sha256(('admin123' + SALT).encode()).hexdigest(),
        'role': 'admin'
    },
    'monitor': {
        'password_hash': hashlib.sha256(('monitor456' + SALT).encode()).hexdigest(),
        'role': 'monitor'  # 只读角色
    }
}

# Session配置
SESSION_CONFIG = {
    'SECRET_KEY': os.environ.get('WAF_SECRET_KEY', 'your_secret_key_here'),
    'PERMANENT_SESSION_LIFETIME': timedelta(hours=8)
}

def verify_password(username, password):
    """验证用户名和密码"""
    if username not in ADMIN_CONFIG:
        return False
    
    password_hash = hashlib.sha256((password + SALT).encode()).hexdigest()
    return password_hash == ADMIN_CONFIG[username]['password_hash']

def get_user_role(username):
    """获取用户角色"""
    return ADMIN_CONFIG.get(username, {}).get('role') 