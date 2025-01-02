import socket
import threading
import paramiko
from logs import log_attack
from generate import VirtualEnvironment

class SSHHoneypot(paramiko.ServerInterface):
    def __init__(self):
        self.client_ip = None
        self.event = threading.Event()
        self.virtual_env = VirtualEnvironment()
        self.channel = None

    def check_auth_password(self, username, password):
        # 记录所有尝试的用户名和密码
        log_attack(
            type="ssh_bruteforce",
            details=f"尝试使用用户名: {username} 密码: {password}",
            blocked=True,
            ip=self.client_ip
        )
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.channel = channel
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def handle_session(self):
        if self.channel is None:
            return
        
        self.channel.send('Welcome to Ubuntu 20.04.4 LTS\r\n$ ')
        
        buffer = ''
        while True:
            char = self.channel.recv(1).decode('utf-8', errors='ignore')
            if not char:
                break
                
            if char == '\r':
                command = buffer.strip()
                if command:
                    result = self.virtual_env.execute_command(command)
                    output = result.get('output', '')
                    self.channel.send(f'\r\n{output}\r\n$ ')
                else:
                    self.channel.send('\r\n$ ')
                buffer = ''
            elif char == '\x03':  # Ctrl+C
                self.channel.send('^C\r\n$ ')
                buffer = ''
            else:
                buffer += char
                self.channel.send(char)

def handle_client(client, addr, host_key):
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        
        ssh = SSHHoneypot()
        ssh.client_ip = addr[0]
        
        transport.start_server(server=ssh)
        
        # 等待客户端认证
        chan = transport.accept(20)
        if chan is None:
            return
            
        ssh.handle_session()
            
    except Exception as e:
        print(f"处理SSH客户端错误: {e}")
    finally:
        try:
            transport.close()
        except:
            pass

def start_ssh_server(port=22):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(100)
        
        host_key = paramiko.RSAKey(filename='keys/ssh_host_rsa')

        while True:
            client, addr = sock.accept()
            thread = threading.Thread(target=handle_client, args=(client, addr, host_key))
            thread.daemon = True
            thread.start()
            
    except Exception as e:
        print(f"SSH服务器错误: {e}") 