from logs import log_attack
import time
from generate import VirtualEnvironment
from utils import get_client_ip
import re

# 创建虚拟环境实例
virtual_env = VirtualEnvironment()

def simulate_sql_injection(request):
    """模拟SQL注入攻击检测"""
    query = request.form.get('query', '').strip()
    
    if not query:
        return {
            "status": "ok",
            "output": "No query executed",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    # 检测SQL注入特征
    dangerous_patterns = {
        "union": r"union\s+select",
        "select": r"select\s+.+\s+from",
        "comment": r"--|\#",
        "drop": r"drop\s+table",
        "delete": r"delete\s+from",
        "update": r"update\s+.+\s+set",
        "insert": r"insert\s+into",
        "or": r"'\s*or\s*'1'\s*=\s*'1",
        "admin": r"admin'--",
        "quote": r"'|\""
    }

    # 检查是否匹配危险模式
    detected_patterns = []
    for pattern_name, pattern in dangerous_patterns.items():
        if re.search(pattern, query, re.IGNORECASE):
            detected_patterns.append(pattern_name)

    # 检测到SQL注入模式时记录日志
    if detected_patterns:
        log_attack(
            type="SQL Injection",
            details=f"检测到SQL注入 | 查询: {query} | 模式: {', '.join(detected_patterns)}",
            blocked=True,
            ip=get_client_ip(request)
        )
        return {
            "status": "blocked",
            "output": "SQL injection detected",
            "detected_patterns": detected_patterns,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "query": query
        }

    # 使用虚拟环境执行查询
    result = virtual_env.execute_query(query)

    # 返回查询结果
    return {
        "status": "ok",
        "output": result["output"] if result["status"] == "success" else "Query execution failed",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "query": query
    }
