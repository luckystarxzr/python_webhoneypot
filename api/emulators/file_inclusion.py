from logs import log_attack
import time
from generate import VirtualEnvironment
from utils import get_client_ip

# 创建虚拟环境实例
virtual_env = VirtualEnvironment()

def simulate_file_inclusion(request):
    """模拟文件包含攻击检测"""
    filepath = request.form.get('file', '').strip()

    # 模拟处理延迟
    time.sleep(0.5)

    if not filepath:
        return {
            "status": "ok",
            "output": "No file specified",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    # 检测文件包含的违禁词
    dangerous_patterns = [
        "etc/passwd", "../", "..\\", "boot.ini",
        "windows\\", "system32", "<script>", "eval(",
        "ls", "whoami", "pwd", "date"
    ]

    # 检测是否包含危险模式
    detected_patterns = [p for p in dangerous_patterns if p.lower() in filepath.lower()]

    if detected_patterns:
        # 记录日志，包含具体的检测模式和文件路径
        log_attack(
            type="File Inclusion",
            details=f"{filepath} | Detected patterns: {', '.join(detected_patterns)}",
            blocked=True,
            ip=get_client_ip(request)
        )
        return {
            "status": "blocked",
            "reason": f"File inclusion attempt detected: {filepath} | Detected patterns: {', '.join(detected_patterns)}",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    # 使用虚拟环境读取文件
    content = virtual_env.read_file(filepath)

    # 检查虚拟环境返回的文件读取结果
    if content == "Invalid file path" or content == "File not found":
        log_attack(
            "File Inclusion",
            f"Invalid file path attempted: {filepath}",
            blocked=True,
            ip=get_client_ip(request)
        )
        return {
            "status": "blocked",
            "reason": f"File inclusion attempt detected: {filepath}",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    return {
        "status": "ok",
        "file_content": content,
        "filepath": filepath,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
