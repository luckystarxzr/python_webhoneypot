from datetime import datetime, timedelta
from collections import defaultdict
import json
from config import LOG_FILE, PER_PAGE
from utils import format_datetime, safe_json_loads, get_client_ip

def get_attack_statistics():
    """获取攻击统计数据"""
    stats = {
        'total_attacks': 0,
        'attack_types': defaultdict(int),
        'top_ips': defaultdict(int),
        'recent_attacks': [],
        'timestamp': format_datetime(datetime.now())
    }
    
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    # 使用safe_json_loads替代json.loads
                    log_entry = safe_json_loads(line.strip())
                    if not log_entry:
                        continue
                        
                    stats['total_attacks'] += 1
                    stats['attack_types'][log_entry.get('type', 'unknown')] += 1
                    stats['top_ips'][log_entry.get('ip', 'unknown')] += 1
                    
                    # 格式化时间戳
                    if 'timestamp' in log_entry:
                        log_entry['timestamp'] = format_datetime(log_entry['timestamp'])
                    
                    # 只保留最近的10次攻击
                    if len(stats['recent_attacks']) < 10:
                        stats['recent_attacks'].append(log_entry)
                except (json.JSONDecodeError, ValueError):
                    continue
    except FileNotFoundError:
        pass
    
    return stats

def get_detailed_attacks(page=1, per_page=PER_PAGE):
    """获取详细的攻击记录"""
    attacks = []
    try:
        with open(LOG_FILE, 'r') as f:
            all_attacks = []
            for line in f:
                # 使用safe_json_loads替代json.loads
                attack = safe_json_loads(line.strip())
                if attack:
                    # 格式化时间戳
                    if 'timestamp' in attack:
                        attack['timestamp'] = format_datetime(attack['timestamp'])
                    all_attacks.append(attack)
            
        # 分页
        start = (page - 1) * per_page
        end = start + per_page
        attacks = all_attacks[start:end]
        total_pages = (len(all_attacks) + per_page - 1) // per_page
        
        return {
            'attacks': attacks,
            'page': page,
            'total_pages': total_pages,
            'total_attacks': len(all_attacks),
            'timestamp': format_datetime(datetime.now())
        }
    except FileNotFoundError:
        return {
            'attacks': [],
            'page': 1,
            'total_pages': 1,
            'total_attacks': 0,
            'timestamp': format_datetime(datetime.now())
        }

def get_attack_analytics(period='day'):
    """获取攻击分析数据"""
    now = datetime.now()
    if period == 'day':
        delta = timedelta(days=1)
    elif period == 'week':
        delta = timedelta(weeks=1)
    elif period == 'month':
        delta = timedelta(days=30)
    else:
        delta = timedelta(days=1)
    
    analytics = {
        'timeline': defaultdict(int),
        'attack_types': defaultdict(int),
        'ip_distribution': defaultdict(int),
        'user_agents': defaultdict(int),
        'timestamp': format_datetime(now)
    }
    
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    # 使用safe_json_loads替代json.loads
                    log_entry = safe_json_loads(line.strip())
                    if not log_entry:
                        continue
                        
                    timestamp = datetime.strptime(
                        log_entry.get('timestamp', ''), 
                        '%Y-%m-%d %H:%M:%S'
                    )
                    
                    if now - timestamp <= delta:
                        date_key = format_datetime(timestamp)
                        analytics['timeline'][date_key] += 1
                        analytics['attack_types'][log_entry.get('type', 'unknown')] += 1
                        analytics['ip_distribution'][log_entry.get('ip', 'unknown')] += 1
                        analytics['user_agents'][log_entry.get('user_agent', 'unknown')] += 1
                except (json.JSONDecodeError, ValueError):
                    continue
    except FileNotFoundError:
        pass
    
    return analytics 