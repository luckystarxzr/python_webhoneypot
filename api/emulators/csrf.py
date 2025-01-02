from logs import log_attack
import time
from generate import VirtualEnvironment
from utils import get_client_ip
import logging

# 创建虚拟环境实例
virtual_env = VirtualEnvironment()

# 创建 logger 实例
logger = logging.getLogger(__name__)

def simulate_csrf(request):
    """模拟CSRF攻击检测"""
    try:
        # 模拟处理延迟
        time.sleep(0.5)
        
        # 获取请求头信息
        referer = request.headers.get('Referer', '')
        expected_referer = request.host_url
        
        # 使用虚拟环境检测CSRF
        result = virtual_env.csrf(referer, expected_referer)
        
        if result["status"] == "blocked":
            log_attack(
                type="CSRF",
                details=f"检测到CSRF攻击 | Referer: {referer}",
                blocked=True,
                ip=get_client_ip(request)
            )
            return {
                **result,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "request_headers": {
                    "referer": referer,
                    "expected": expected_referer
                }
            }
        
        return {
            **result,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "request_headers": {
                "referer": referer,
                "expected": expected_referer
            }
        }
    except Exception as e:
        logger.error(f"CSRF模拟错误: {str(e)}")
        return {
            "status": "error",
            "output": f"Internal server error: {str(e)}",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
