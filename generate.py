import random
import time
#随机生成数据
def generate_environment(file_path):
    if not file_path or ".." in file_path:
        return "Invalid file path"
    content_type = random.choice(["text", "binary", "log"])
    if content_type == "text":
        return f"Mock text content of {file_path}: {random.randint(1000, 9999)}"
    elif content_type == "binary":
        return f"Mock binary data of {file_path}: {random.getrandbits(8)}"
    elif content_type == "log":
        return f"Log entry for {file_path}: Timestamp {random.randint(1000000000, 9999999999)}"
class VirtualEnvironment:
    def __init__(self):
        # 扩展虚拟文件系统
        self.filesystem = {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash",
            "/etc/shadow": "Permission denied",
            "/var/log/auth.log": "May 20 15:23:01 localhost sshd[1234]: Failed password for root from 192.168.1.100",
            "/var/www/html/index.php": "<?php phpinfo(); ?>",
            "/home/user/documents/secret.txt": "Confidential information",
            "public/index.html": "<html><body>Welcome to our site</body></html>",
            "public/about.html": "<html><body>About Us page</body></html>",
            "templates/header.php": "<header>Site Header</header>",
            "templates/footer.php": "<footer>Site Footer</footer>"
        }
        
        # 扩展命令输出
        self.commands = {
            "ls": self._generate_ls_output(),
            "whoami": "www-data",
            "pwd": "/var/www/html",
            "date": self._get_current_time(),
            "cat": self._handle_cat,
            "ps": self._generate_ps_output(),
            "netstat": self._generate_netstat_output(),
            "ifconfig": self._generate_ifconfig_output()
        }

    def _get_current_time(self):
        """生成当前时间"""
        return time.strftime("%a %b %d %H:%M:%S %Z %Y")

    def _generate_ls_output(self):
        """生成更真实的ls命令输出"""
        files = [
            "index.php",
            "config.php",
            "uploads/",
            "images/",
            "css/",
            "js/",
            ".htaccess"
        ]
        return "\n".join(files)

    def _generate_ps_output(self):
        """生成虚拟进程列表"""
        processes = [
            "apache2",
            "mysql",
            "php-fpm",
            "sshd",
            "cron"
        ]
        return "\n".join(f"{i} {proc}" for i, proc in enumerate(processes, 1))

    def _generate_netstat_output(self):
        """生成虚拟网络连接"""
        return "tcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN\ntcp 0 0 0.0.0.0:443 0.0.0.0:* LISTEN"

    def _generate_ifconfig_output(self):
        """生成虚拟网络接口信息"""
        return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500\n        inet 192.168.1.100"

    def _handle_cat(self, filepath):
        """处理cat命令"""
        return self.filesystem.get(filepath, f"cat: {filepath}: No such file or directory")

    def execute_command(self, command):
        """执行命令并返回结果"""
        if not command or ".." in command:
            return {
                "status": "error",
                "output": "Invalid command"
            }

        # 解析命令和参数
        parts = command.split()
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        if cmd in self.commands:
            if callable(self.commands[cmd]):
                output = self.commands[cmd](*args)
            else:
                output = self.commands[cmd]
            return {
                "status": "success",
                "output": output
            }

        return {
            "status": "error",
            "output": f"Command not found: {cmd}"
        }

    def read_file(self, filepath):
        if not filepath or ".." in filepath:
            return "Invalid file path"
        return self.filesystem.get(filepath, "File not found")

    def xss(self, payload):
        if "<script>" in payload or "javascript:" in payload or "onerror" in payload:
            return {
                "status": "blocked",
                "reason": "Potential XSS detected",
                "payload": payload
            }
        return {
            "status": "ok",
            "output": f"Rendered content: {payload}"
        }

    def sql_injection(self, query):
        sql_keywords = [
            "' OR 1=1", "UNION SELECT", "--", ";", "DROP TABLE", "INSERT INTO",
            "DELETE FROM", "UPDATE", "xp_cmdshell", "EXEC", "CAST(", "CONVERT("
        ]
        if any(keyword in query.upper() for keyword in sql_keywords):
            return {
                "status": "blocked",
                "reason": "Potential SQL Injection detected",
                "query": query
            }
        return {
            "status": "ok",
            "output": f"Query executed: {query}"
        }

    def csrf(self, referer, expected_referer):
        if referer != expected_referer:
            return {
                "status": "blocked",
                "reason": "Potential CSRF detected",
                "referer": referer
            }
        return {
            "status": "ok",
            "output": "Request validated"
        }

    def directory_traversal(self, filepath):
        if ".." in filepath or filepath.startswith("/etc"):
            return {
                "status": "blocked",
                "reason": "Potential Directory Traversal detected",
                "filepath": filepath
            }
        return {
            "status": "ok",
            "output": f"Accessed file: {filepath}"
        }

