from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from logs import log_attack
from generate import VirtualEnvironment
import os

class HoneypotFTPHandler(FTPHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.virtual_env = VirtualEnvironment()

    def on_login_failed(self, username, password):
        log_attack(
            type="ftp_bruteforce",
            details=f"尝试使用用户名: {username} 密码: {password}",
            blocked=True,
            ip=self.remote_ip
        )

    def on_file_sent(self, file):
        log_attack(
            type="ftp_download",
            details=f"下载文件: {file}",
            blocked=False,
            ip=self.remote_ip
        )

    def on_file_received(self, file):
        log_attack(
            type="ftp_upload",
            details=f"上传文件: {file}",
            blocked=True,
            ip=self.remote_ip
        )
        # 删除上传的文件
        try:
            os.remove(file)
        except:
            pass

    def on_incomplete_file_sent(self, file):
        log_attack(
            type="ftp_incomplete_download",
            details=f"未完成的文件下载: {file}",
            blocked=False,
            ip=self.remote_ip
        )

    def on_incomplete_file_received(self, file):
        log_attack(
            type="ftp_incomplete_upload",
            details=f"未完成的文件上传: {file}",
            blocked=True,
            ip=self.remote_ip
        )
        # 删除未完成的文件
        try:
            os.remove(file)
        except:
            pass

def setup_virtual_files():
    """设置虚拟文件系统"""
    os.makedirs('./ftp_files', exist_ok=True)
    virtual_env = VirtualEnvironment()
    
    # 创建一些诱饵文件
    files = {
        'readme.txt': 'Welcome to FTP server\n',
        'config.ini': '[database]\nhost=localhost\nuser=admin\n',
        'backup/': None,
        'uploads/': None,
        'www/': None
    }
    
    for path, content in files.items():
        full_path = os.path.join('./ftp_files', path)
        if content is None:  # 目录
            os.makedirs(full_path, exist_ok=True)
        else:  # 文件
            with open(full_path, 'w') as f:
                f.write(content)

def start_ftp_server(port=21):
    try:
        # 设置虚拟文件系统
        setup_virtual_files()
        
        authorizer = DummyAuthorizer()
        # 添加匿名用户
        authorizer.add_anonymous('./ftp_files', perm='elr')
        # 添加一个测试用户
        authorizer.add_user('test', 'test123', './ftp_files', perm='elradfmw')
        
        handler = HoneypotFTPHandler
        handler.authorizer = authorizer
        handler.banner = "FTP Server Ready"
        
        server = FTPServer(('0.0.0.0', port), handler)
        server.serve_forever()
        
    except Exception as e:
        print(f"FTP服务器错误: {e}")