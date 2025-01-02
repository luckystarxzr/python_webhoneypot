from logs import log_attack
import time
from generate import VirtualEnvironment
from utils import get_client_ip
import re

# 创建虚拟环境实例
virtual_env = VirtualEnvironment()

def simulate_xss(request):
    """模拟XSS攻击检测"""
    input_data = request.form.get('payload', '').strip()

    if not input_data:
        return {
            "status": "ok",
            "output": "No input provided",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    # 使用正则表达式检测XSS特征
    dangerous_patterns = {
        "script_tag": r"<script.*?>.*?</script>",      # 匹配 <script> 标签
        "javascript_protocol": r"javascript:",          # 匹配 javascript:
        "event_handler": r"on\w+\s*=",                 # 匹配事件处理器 (onload=, onclick= 等)
        "eval": r"eval\(",                             # 匹配 eval(
        "alert": r"alert\(",                           # 匹配 alert(
        "cookie": r"document\.cookie",                 # 匹配 document.cookie
        "img_tag": r"<img.*?>",                       # 匹配 <img> 标签
        "iframe_tag": r"<iframe.*?>",                 # 匹配 <iframe> 标签
        "svg_tag": r"<svg.*?>",                       # 匹配 <svg> 标签
        "base64": r"base64",                          # 匹配 base64 编码
        "data_uri": r"data:",                         # 匹配 data: URI
        "vbscript": r"vbscript:"                      # 匹配 vbscript:
    }

    # 检查是否匹配危险模式
    detected_patterns = []
    for pattern_name, pattern in dangerous_patterns.items():
        if re.search(pattern, input_data, re.IGNORECASE):
            detected_patterns.append(pattern_name)

    # 如果检测到XSS模式，记录日志并返回警告
    if detected_patterns:
        log_attack(
            type="XSS",
            details=f"检测到XSS攻击 | 输入: {input_data} | 模式: {', '.join(detected_patterns)}",
            blocked=True,
            ip=get_client_ip(request)
        )
        return {
            "status": "blocked",
            "output": "XSS attack detected",
            "detected_patterns": detected_patterns,
            "input": input_data,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    # 使用虚拟环境处理输入
    result = virtual_env.process_input(input_data)

    # 返回处理结果
    return {
        "status": "ok",
        "output": result["output"] if result["status"] == "success" else "Input processing failed",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
