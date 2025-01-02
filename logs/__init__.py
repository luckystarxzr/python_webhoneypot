import os
from config.config import LOG_FILE

def ensure_log_dir():
    """确保日志目录存在"""
    log_dir = os.path.dirname(LOG_FILE)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

# 创建日志目录
ensure_log_dir()

# 从 logs.py 导入所需函数
from .logs import log_attack, get_logs, export_logs

__all__ = ['log_attack', 'get_logs', 'export_logs']