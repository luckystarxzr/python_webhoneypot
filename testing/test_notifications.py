import logging
from notifications import AttackNotifier

# 配置日志输出到控制台
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def test_attack_notifier():
    # 创建一个 AttackNotifier 实例
    notifier = AttackNotifier()

    # 模拟攻击细节
    attack_details = {
        'type': 'Command Injection',
        'ip': '192.168.1.1',
        'details': '检测到命令注入 | 命令: ls | 模式: ls',
        'blocked': True
    }

    # 模拟多次攻击以触发通知
    for _ in range(5):
        notifier.check_and_notify(attack_details)

if __name__ == "__main__":
    test_attack_notifier() 