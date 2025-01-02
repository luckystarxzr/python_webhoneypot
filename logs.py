import logging
import os
from datetime import datetime
import json
import traceback

from logs.logs import is_valid_ip, calculate_severity
from notifications import notifier


# 配置日志记录器
def setup_attack_logger():
    logger = logging.getLogger('attack_logger')
    logger.setLevel(logging.INFO)

    # 创建 FileHandler
    handler = logging.FileHandler('logs/attacks.log')
    handler.setLevel(logging.INFO)

    # 创建格式化器
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # 添加处理器到日志记录器
    logger.addHandler(handler)

    return logger


def log_attack(type, details, blocked, ip):
    """记录攻击并发送通知"""
    try:
        # 验证IP地址
        if not is_valid_ip(ip) and not ip.startswith('container:'):
            print(f"Invalid IP address: {ip}")
            ip = "unknown"

        # 创建日志条目
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": type,
            "ip": ip,
            "details": details,
            "blocked": blocked,
            "severity": calculate_severity(type, details)  # 添加严重程度
        }

        # 写入日志文件
        log_dir = 'logs'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        log_file = os.path.join(log_dir, 'attacks.log')
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')

        # 发送通知
        notifier.check_and_notify(log_entry)

    except Exception as e:
        print(f"Error logging attack: {e}")
        logging.error(f"Error logging attack: {str(e)}\n{traceback.format_exc()}") 