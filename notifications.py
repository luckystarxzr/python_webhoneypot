import smtplib
from email.mime.text import MIMEText
from email.header import Header
from datetime import datetime
from config.config import SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, ADMIN_EMAIL
from threading import Lock
import logging

class AttackNotifier:
    def __init__(self):
        self.attack_count = 0
        self.last_notify_time = datetime.now()
        self.lock = Lock()
        self.logger = logging.getLogger('AttackNotifier')
        self.logger.setLevel(logging.DEBUG)

    def check_and_notify(self, attack_details):
        with self.lock:
            self.attack_count += 1
            self.logger.debug(f"Current attack count: {self.attack_count}")
            self.logger.debug(f"Attack details: {attack_details}")

            # 立即发送通知
            self.logger.info("Sending notification.")
            self.send_notification(attack_details)

    def send_notification(self, attack_details):
        """发送通知"""
        message = self.format_message(attack_details)
        self.logger.debug(f"Formatted message: {message}")

        try:
            self.send_email(message)
            self.logger.info("Email sent successfully.")
        except Exception as e:
            self.logger.error(f"邮件发送失败: {e}")

    def format_message(self, attack_details):
        """格式化通知消息"""
        return f"""
检测到新的攻击行为！

时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
攻击类型: {attack_details.get('type', '未知')}
攻击IP: {attack_details.get('ip', '未知')}
攻击详情: {attack_details.get('details', '无')}
状态: {'已拦截' if attack_details.get('blocked', True) else '未拦截'}

请及时查看系统日志获取更多信息。
        """

    def send_email(self, message):
        """发送QQ邮件通知"""
        self.logger.debug("Preparing to send email.")
        msg = MIMEText(message, 'plain', 'utf-8')
        msg['Subject'] = Header('【WAF告警】检测到新的攻击行为', 'utf-8')
        msg['From'] = SMTP_USER
        msg['To'] = ADMIN_EMAIL

        try:
            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
                self.logger.debug("Logging into SMTP server.")
                server.login(SMTP_USER, SMTP_PASSWORD)
                self.logger.debug("Sending email.")
                server.sendmail(SMTP_USER, [ADMIN_EMAIL], msg.as_string())
                self.logger.info("Email sent successfully.")
        except Exception as e:
            self.logger.error(f"Error during email sending: {e}")

# 创建全局通知器实例
notifier = AttackNotifier() 