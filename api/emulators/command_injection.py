from logs import log_attack
import re
import time
from generate import VirtualEnvironment
from utils import get_client_ip

# 创建虚拟环境实例
virtual_env = VirtualEnvironment()

def simulate_command_injection(request):
    """模拟命令注入攻击检测"""
    try:
        # 获取请求数据
        data = request.get_json() if request.is_json else request.form
        command = data.get('cmd', '').strip()

        # 模拟处理延迟
        time.sleep(0.5)

        if not command:
            return {
                "status": "ok",
                "output": "No command executed",
                "shell_type": "bash",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

        # 检测危险字符和模式,
        dangerous_patterns = {
            "pipe": r"\|",
            "semicolon": r";",
            "ampersand": r"&",
            "redirect": r">|<",
            "backtick": r"`",
            "dollar": r"\$\(",
            "path_traversal": r"\.\.",
            "ls": r"\bls\b",
            "whoami": r"\bwhoami\b",
            "pwd": r"\bpwd\b",
            "date": r"\bdate\b"
        }

        # 检查危险模式
        detected_patterns = []
        for pattern_name, pattern in dangerous_patterns.items():
            if re.search(pattern, command):
                detected_patterns.append(pattern_name)

        # 如果检测到危险模式，记录日志并阻止执行
        if detected_patterns:
            log_attack(
                type="Command Injection",
                details=f"检测到命令注入 | 命令: {command} | 模式: {', '.join(detected_patterns)}",
                blocked=True,
                ip=get_client_ip(request)
            )

            return {
                "status": "blocked",
                "output": "Permission denied: Dangerous character detected",
                "shell_type": "bash",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "detected_patterns": detected_patterns,
                "error_code": 126
            }

        # 使用虚拟环境执行命令
        result = virtual_env.execute_command(command)

        # 正常命令直接返回结果
        if result["status"] == "success":
            return {
                "status": "ok",
                "output": result["output"],
                "shell_type": "bash",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "command": command,
                "exit_code": 0
            }

        # 未知命令返回错误，但不记录日志
        return {
            "status": "error",
            "output": result["output"],
            "shell_type": "bash",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "error_code": 127
        }

    except Exception as e:
        # 系统错误时记录日志
        log_attack(
            "Command Injection",
            details=f"系统错误: {str(e)} | 输入: {command if 'command' in locals() else 'unknown'}",
            blocked=False,
            ip=get_client_ip(request)
        )
        return {
            "status": "error",
            "output": "Internal server error",
            "shell_type": "bash",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "error_code": 500
        }
