import os
import logging
from datetime import datetime
import mysql.connector
from utils import format_datetime, get_client_ip

# 数据库配置
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "123456",
    "database": "honeypot_db"
}

def init_db():
    """初始化数据库"""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # 创建攻击记录表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(255),
                user_agent VARCHAR(255),
                attack_type VARCHAR(50),
                payload TEXT,
                status VARCHAR(20),
                details TEXT
            )
        ''')
        
        # 创建请求日志表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(255),
                user_agent VARCHAR(255),
                method VARCHAR(10),
                url VARCHAR(2083),
                status_code INT,
                response_time FLOAT
            )
        ''')
        
        conn.commit()
        logging.info("数据库初始化成功")
        
    except mysql.connector.Error as e:
        logging.error(f"数据库初始化失败: {e}")
        
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

def log_attack(attack_type, payload, request, status="blocked", details=None):
    """记录攻击信息到数据库"""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        ip_address = get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "Unknown")
        timestamp = format_datetime(datetime.now())
        
        query = '''
            INSERT INTO attacks 
            (timestamp, ip_address, user_agent, attack_type, payload, status, details)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        '''
        cursor.execute(query, (
            timestamp,
            ip_address,
            user_agent,
            attack_type,
            payload,
            status,
            details or ""
        ))
        
        conn.commit()
        logging.info(f"攻击记录已保存: {attack_type} from {ip_address}")
        
    except mysql.connector.Error as e:
        logging.error(f"数据库记录失败: {e}")
        
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

def log_request(request, status_code, response_time):
    """记录普通请求信息"""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        query = '''
            INSERT INTO requests 
            (timestamp, ip_address, user_agent, method, url, status_code, response_time)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        '''
        cursor.execute(query, (
            format_datetime(datetime.now()),
            get_client_ip(request),
            request.headers.get("User-Agent", "Unknown"),
            request.method,
            request.url,
            status_code,
            response_time
        ))
        
        conn.commit()
        
    except mysql.connector.Error as e:
        logging.error(f"请求记录失败: {e}")
        
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

def get_recent_attacks(limit=10):
    """获取最近的攻击记录"""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        query = '''
            SELECT * FROM attacks 
            ORDER BY timestamp DESC 
            LIMIT %s
        '''
        cursor.execute(query, (limit,))
        attacks = cursor.fetchall()
        
        # 格式化时间戳
        for attack in attacks:
            attack['timestamp'] = format_datetime(attack['timestamp'])
            
        return attacks
        
    except mysql.connector.Error as e:
        logging.error(f"获取攻击记录失败: {e}")
        return []
        
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# 初始化数据库
if __name__ == "__main__":
    init_db()
