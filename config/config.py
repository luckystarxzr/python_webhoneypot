import os
import hashlib
from datetime import timedelta
import json
import secrets
import string


def generate_random_string(length=32):
    """生成指定长度的随机字符串"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def get_or_create_secret(filename, key_name):
    """获取或创建密钥值"""
    try:
        with open(filename, 'r') as f:
            secrets_dict = json.load(f)
            if key_name in secrets_dict:
                return secrets_dict[key_name]
    except (FileNotFoundError, json.JSONDecodeError):
        secrets_dict = {}

    # 生成新的随机值
    new_secret = generate_random_string(32)
    secrets_dict[key_name] = new_secret

    # 保存到文件
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w') as f:
        json.dump(secrets_dict, f)

    return new_secret


# 基础配置
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
DATA_DIR = os.path.join(LOG_DIR, 'attacks.log')
LOG_FILE = os.path.join(LOG_DIR, 'debug.log')
PER_PAGE = 20
RULES_FILE = os.path.join(BASE_DIR, 'rules/waf_rules.json')

SECRETS_FILE = os.path.join(BASE_DIR, 'config', 'secrets.json')

# 获取或生成随机盐值
SALT = os.environ.get('WAF_SALT', get_or_create_secret(SECRETS_FILE, 'salt'))

# 获取或生成随机会话密钥
SECRET_KEY = os.environ.get('WAF_SECRET_KEY', get_or_create_secret(SECRETS_FILE, 'secret_key'))

# Session配置
PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

# 管理员账号配置
ADMIN_USERS = {
    'admin': {
        'password_hash': hashlib.sha256(('a654321' + SALT).encode()).hexdigest(),
        'role': 'admin',
        'description': '超级管理员'
    },
    'monitor': {
        'password_hash': hashlib.sha256(('m654321' + SALT).encode()).hexdigest(),
        'role': 'monitor',
        'description': '只读用户'
    }
}

# 登录配置
LOGIN_LIMIT = {
    'max_attempts': 5,  # 最大尝试次数
    'lock_time': 3600,  # 锁定时间（秒）
    'attempt_timeout': 3600  # 尝试记录超时时间（秒）
}

# 通知配置
NOTIFICATION_CONFIG = {
    'enabled': True,
    'min_severity': 3,  # 最小通知严重度
    'methods': ['email']  # 通知方式
}

# 蜜罐配置
HONEYPOT_CONFIG = {
    'ssh': {
        'enabled': True,
        'port': 22,
        'max_connections': 100
    },
    'ftp': {
        'enabled': True,
        'port': 21,
        'max_connections': 100
    },
    'web': {
        'enabled': True,
        'port': 80,
        'max_connections': 200
    }
}

# 日志配置
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "attacks.log")
LOG_FORMAT = '%(asctime)s - %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# 数据配置
DATA_DIR = os.path.join(BASE_DIR, "data")
RULES_FILE = os.path.join(DATA_DIR, "rules.json")

# 安全配置
ALLOWED_EXTENSIONS = {'txt', 'log', 'json', 'csv'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

# 分页配置
PER_PAGE = 20
MAX_PAGE_DISPLAY = 5

# 导出配置
EXPORT_FORMATS = ['csv', 'json']
TEMP_DIR = os.path.join(BASE_DIR, "temp")

# QQ邮箱配置
SMTP_SERVER = 'smtp.qq.com'
SMTP_PORT = 465
SMTP_USER = '2128702641@qq.com'  # 你的QQ邮箱
SMTP_PASSWORD = 'twjxrzcsfdeujcec'  # QQ邮箱授权码
ADMIN_EMAIL = '3447470174@qq.com'  # 接收通知的邮箱

# 确保必要的目录存在
for directory in [LOG_DIR, DATA_DIR, TEMP_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory) 