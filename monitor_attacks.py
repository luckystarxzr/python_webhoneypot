import time
import json
import logging
from notifications import AttackNotifier

# 配置日志输出到控制台
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def monitor_attacks(log_file_path, notifier, check_interval=5):
    """监控攻击日志文件并发送通知"""
    last_count = 0

    while True:
        try:
            with open(log_file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                current_count = len(lines)

                # 检查是否有新记录
                if current_count > last_count:
                    new_entries = lines[last_count:current_count]
                    logging.info(f"检测到{len(new_entries)}条新攻击记录，准备发送通知。")

                    # 合并新记录并发送通知
                    combined_details = "\n".join(new_entries)
                    logging.debug(f"合并的新记录详情: {combined_details}")
                    notifier.check_and_notify({
                        'type': 'Batch Notification',
                        'ip': 'N/A',
                        'details': combined_details,
                        'blocked': True
                    })

                    # 更新记录计数
                    last_count = current_count

        except Exception as e:
            logging.error(f"监控过程中发生错误: {e}")

        # 等待下一个检查周期
        time.sleep(check_interval)

if __name__ == "__main__":
    notifier = AttackNotifier()
    monitor_attacks('logs/attacks.log', notifier) 