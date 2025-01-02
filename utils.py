import os
import json
from datetime import datetime
from config.config import ALLOWED_EXTENSIONS, MAX_CONTENT_LENGTH

def allowed_file(filename):
    """检查文件扩展名是否允许"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def format_datetime(dt):
    """格式化日期时间"""
    if isinstance(dt, str):
        try:
            dt = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return dt
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def safe_json_loads(data, default=None):
    """安全的JSON解析"""
    if not data:
        return default if default is not None else {}
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else {}

def get_client_ip(request):
    """获取客户端真实IP"""
    if not request:
        return "Unknown"
    if request.headers.get('X-Forwarded-For'):
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr

def sanitize_filename(filename):
    """清理文件名"""
    if not filename:
        return ""
    return "".join(c for c in filename if c.isalnum() or c in "._- ")

def check_file_size(file_size):
    """检查文件大小是否超过限制"""
    return file_size <= MAX_CONTENT_LENGTH 