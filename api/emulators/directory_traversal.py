from logs import log_attack
import time
from generate import VirtualEnvironment
from utils import get_client_ip
import logging
import traceback

# 配置调试日志
logging.basicConfig(
    filename='logs/debug.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 创建虚拟环境实例
virtual_env = VirtualEnvironment()

def simulate_directory_traversal(request):
    """模拟目录遍历攻击检测"""
    try:
        # 调试: 打印请求信息
        logger.debug(f"Request form data: {request.form}")
        logger.debug(f"Request headers: {request.headers}")
        
        path = request.form.get('path', '').strip()
        logger.debug(f"Received path: {path}")

        if not path:
            logger.info("No path provided")
            return {
                "status": "ok",
                "output": "No path provided",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

        # 检测目录遍历特征
        dangerous_patterns = [
            "../", "..\\", "..", "/etc/",
            "c:\\", "windows\\", "boot.ini",
            "/proc/", "/var/log/"
        ]
        logger.debug(f"Checking patterns against path: {path}")

        # 检查是否包含危险模式
        detected_patterns = [p for p in dangerous_patterns if p.lower() in path.lower()]
        logger.debug(f"Detected patterns: {detected_patterns}")

        # 只有检测到危险模式时才记录日志
        if detected_patterns:
            try:
                logger.info(f"Attack detected with patterns: {detected_patterns}")
                log_attack(
                    type="Directory Traversal",
                    details=f"检测到目录遍历攻击 | 路径: {path} | 模式: {''.join(detected_patterns)}",
                    blocked=True,
                    ip=get_client_ip(request)
                )
            except Exception as log_error:
                logger.error(f"Log attack failed: {str(log_error)}")
                logger.error(f"Error traceback: {traceback.format_exc()}")

            return {
                "status": "blocked",
                "output": "Directory traversal detected",
                "detected_patterns": detected_patterns,
                "path": path,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

        logger.info(f"Path accessed successfully: {path}")
        return {
            "status": "ok",
            "output": f"Path '{path}' accessed successfully",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    except Exception as e:
        logger.error(f"Error in simulate_directory_traversal: {str(e)}")
        logger.error(f"Error traceback: {traceback.format_exc()}")
        return {
            "status": "error",
            "output": f"Internal server error: {str(e)}",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
