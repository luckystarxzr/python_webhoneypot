from datetime import datetime
import json
import os
from config.config import DATA_DIR, LOG_FILE
from notifications import notifier
import ipaddress
import logging
import traceback

def is_valid_ip(ip):
    """验证IP地址是否有效"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def log_attack(type, details, blocked, ip):
    try:
        # 验证IP地址
        if not is_valid_ip(ip) and not ip.startswith('container:'):
            print(f"Invalid IP address: {ip}")
            ip = "unknown"
            
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": type,
            "ip": ip,
            "details": details,
            "blocked": blocked,
            "severity": calculate_severity(type, details)  # 添加严重程度
        }
        
        # 确保日志目录存在
        os.makedirs('logs', exist_ok=True)
        
        # 写入日志文件
        with open('logs/attacks.log', 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
            
    except Exception as e:
        print(f"Error logging attack: {e}")
        logging.error(f"Error logging attack: {str(e)}\n{traceback.format_exc()}")
        
def calculate_severity(type, details):
    """计算攻击严重程度"""
    severity = 1  # 默认级别
    
    # 根据攻击类型判断
    if 'Command Injection' in type:
        severity = 4
    elif 'SQL Injection' in type:
        severity = 4
    elif 'XSS' in type:
        severity = 3
    elif 'Directory Traversal' in type:
        severity = 3
    elif 'File Inclusion' in type:
        severity = 3
    
    # 根据特定关键字提高严重程度
    dangerous_keywords = ['rm -rf', 'DROP TABLE', 'DELETE FROM', 'System32']
    if any(keyword in details for keyword in dangerous_keywords):
        severity = 5
        
    return severity

def get_logs(page=1, per_page=20, attack_type=None, date=None, search=None, errors='strict', min_severity=None):
    """获取分页的日志记录"""
    if not os.path.exists(DATA_DIR):
        return [], 0
    
    logs = []
    with open(DATA_DIR, 'r', encoding='utf-8-sig', errors=errors) as f:
        for line in f:
            try:
                log = json.loads(line.strip())
                
                # 应用过滤器
                if attack_type and log['type'] != attack_type:
                    continue
                    
                if date and not log['timestamp'].startswith(date):
                    continue
                    
                if min_severity and log.get('severity', 1) < min_severity:
                    continue
                    
                if search:
                    search_lower = search.lower()
                    if (search_lower not in str(log.get('details', '')).lower() and 
                        search_lower not in str(log.get('ip', '')) and
                        search_lower not in str(log.get('type', '')).lower()):
                        continue
                    
                logs.append(log)
            except json.JSONDecodeError:
                continue
    
    # 按时间戳倒序排序
    logs.sort(key=lambda x: (-x.get('severity', 1), x['timestamp']), reverse=True)
    
    # 计算分页
    total = len(logs)
    start = (page - 1) * per_page
    end = start + per_page
    
    return logs[start:end], total

def export_logs():
    """导出日志记录"""
    try:
        logs, _ = get_logs(page=1, per_page=1000)
        
        export_data = []
        for log in logs:
            export_data.append({
                '时间': log['timestamp'],
                '攻击类型': log['type'],
                'IP地址': log['ip'],
                '详情': log['details'],
                '严重程度': log.get('severity', 1),
                '状态': '已拦截' if log.get('blocked', True) else '已通过'
            })
        
        return export_data
    except Exception as e:
        # 添加错误日志
        logging.error(f"导出日志失败: {str(e)}\n{traceback.format_exc()}")
        return []