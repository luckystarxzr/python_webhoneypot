from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for, make_response
import time
import traceback
from datetime import datetime, timedelta
import json
import sys
import os
import logging
from config.admin import verify_password, get_user_role, SESSION_CONFIG
from logs import get_logs, export_logs, log_attack
from api.emulators import (
    simulate_command_injection,
    simulate_csrf,
    simulate_directory_traversal,
    simulate_file_inclusion,
    simulate_sql_injection,
    simulate_xss
)
from config.config import RULES_FILE
from collections import Counter, defaultdict
from functools import wraps
import random
import re
from notifications import notifier
import threading
from monitor_attacks import monitor_attacks
from notifications import AttackNotifier

app = Flask(__name__)
app.config.update(SESSION_CONFIG)

# 配置日志
logging.basicConfig(
    filename='logs/flask.log',
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# 确保日志目录存在
if not os.path.exists('logs'):
    os.makedirs('logs')

login_attempts = {}


def check_login_attempts(ip):
    """检查登录尝试次数"""
    current_time = time.time()
    if ip in login_attempts:
        attempts = login_attempts[ip]
        # 清理过期的尝试记录
        attempts = [t for t in attempts if current_time - t < 3600]
        login_attempts[ip] = attempts

        if len(attempts) >= 3:  # 最多允许3次尝试
            return False, (attempts[0] + 3600 - current_time)
    return True, None


def load_rules():
    try:
        if not os.path.exists(RULES_FILE):
            # 如果规则文件不存在，创建默认规则
            default_rules = {
                "command_injection": {
                    "patterns": [";", "&&", "||", "|", "`", "$", "(", ")", "<", ">"],
                    "blocked_commands": ["rm", "wget", "curl", "nc", "bash", "sh", "python"]
                },
                "sql_injection": {
                    "patterns": ["'", "\"", "union", "select", "drop", "delete", "update", "insert"],
                    "keywords": ["or", "and", "where", "like", "="]
                },
                "xss": {
                    "patterns": ["<script>", "javascript:", "onerror=", "onload=", "eval("],
                    "tags": ["script", "img", "iframe", "object", "embed"]
                },
                "directory_traversal": {
                    "patterns": ["../", "..\\", "..", "/etc/", "c:\\"],
                    "sensitive_files": ["/etc/passwd", "web.config", ".htaccess"]
                },
                "file_inclusion": {
                    "patterns": ["php://", "file://", "data://", "ftp://", "http://"],
                    "extensions": [".php", ".asp", ".jsp", ".cgi"]
                }
            }
            # 确保目录存在,.
            os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
            # 写入默认规则
            with open(RULES_FILE, 'w', encoding='utf-8') as f:
                json.dump(default_rules, f, indent=4, ensure_ascii=False)
            return default_rules

        # 读取现有规则文件
        with open(RULES_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading rules: {e}")
        return {}


# 加载规则
rules = load_rules()


# 登录验证装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# 登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip = request.remote_addr

        # 检查登录尝试次数
        allowed, locked_until = check_login_attempts(ip)
        if not allowed:
            return render_template('login.html',
                                   error='登录尝试次数过多，请稍后再试',
                                   locked_until=time.strftime('%H:%M:%S',
                                                              time.loc.ltime(time.time() + locked_until)))

        if verify_password(username, password):
            session['logged_in'] = True
            session['username'] = username
            session['role'] = get_user_role(username)
            session.permanent = True
            return redirect(url_for('admin_dashboard'))
        else:
            # 记录失败的登录尝试
            if ip not in login_attempts:
                login_attempts[ip] = []
            login_attempts[ip].append(time.time())
            attempts_left = 3 - len(login_attempts[ip])
            return render_template('login.html',
                                   error='用户名或密码错误',
                                   attempts_left=attempts_left)

    return render_template('login.html')


# 登出路由
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route("/command_injection", methods=['GET'])
def command_injection_page():
    return render_template("command_injection.html")


@app.route("/api/emulators/command_injection", methods=['POST'])
def command_injection_api():
    result = simulate_command_injection(request)
    return jsonify(result)


@app.route("/csrf", methods=['GET'])
def csrf_page():
    return render_template("csrf.html")


@app.route("/api/emulators/csrf", methods=['POST'])
def csrf_api():
    result = simulate_csrf(request)
    return jsonify(result)


@app.route("/directory_traversal", methods=['GET'])
def directory_traversal_page():
    return render_template("directory_traversal.html")


@app.route("/api/emulators/directory_traversal", methods=['POST'])
def directory_traversal_api():
    result = simulate_directory_traversal(request)
    return jsonify(result)


@app.route("/file_inclusion", methods=['GET'])
def file_inclusion_page():
    return render_template("file_inclusion.html")


@app.route("/api/emulators/file_inclusion", methods=['POST'])
def file_inclusion_api():
    result = simulate_file_inclusion(request)
    return jsonify(result)


@app.route("/sql_injection", methods=['GET'])
def sql_injection_page():
    try:
        return render_template("sql_injection.html")
    except Exception as e:
        app.logger.error(f"Error rendering SQL injection page: {str(e)}")
        return "Internal Server Error", 500


@app.route("/api/emulators/sql_injection", methods=['POST'])
def sql_injection_api():
    try:
        result = simulate_sql_injection(request)
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error in SQL injection API: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Internal server error",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }), 500


@app.route("/xss", methods=['GET'])
def xss_page():
    return render_template("xss.html")


@app.route("/api/emulators/xss", methods=['POST'])
def xss_api():
    result = simulate_xss(request)
    return jsonify(result)


def ensure_log_directory():
    try:
        log_dir = 'logs'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # 创建 attacks.log 文件（如果不存在）
        log_file = os.path.join(log_dir, 'attacks.log')
        if not os.path.exists(log_file):
            open(log_file, 'a').close()

        return True
    except Exception as e:
        print(f"创建日志目录或文件失败: {str(e)}")
        return False


def log_attack(type, details, blocked, ip):
    """记录攻击日志"""
    try:
        # 确保日志目录和文件存在
        ensure_log_directory()

        # 创建日志条目
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': type,
            'details': details,
            'blocked': blocked,
            'ip': ip
        }

        # 写入日志文件
        with open('logs/attacks.log', 'a', encoding='utf-8') as f:
            f.write(str(log_entry) + '\n')
            f.flush()  # 确保立即写入

    except Exception as e:
        print(f"记录攻击日志失败: {str(e)}")
        # 可以选择将错误记录到系统日志
        logging.error(f"记录攻击日志失败: {str(e)}")


def get_logs(page=1, per_page=10):
    """获取日志记录"""
    try:
        logs = []
        if os.path.exists('logs/attacks.log'):
            with open('logs/attacks.log', 'r', encoding='utf-8') as f:
                logs = [json.loads(line.strip()) for line in f if line.strip()]
        return logs[(page - 1) * per_page:page * per_page], len(logs)
    except Exception as e:
        app.logger.error(f"读取日志失败: {str(e)}\n{traceback.format_exc()}")
        return [], 0


@app.route('/')
def home():
    """主页"""
    return render_template('index.html')


@app.route('/dashboard')
@app.route('/admin/dashboard')
def admin_dashboard():
    try:
        # 读取日志文件
        logs = []
        try:
            with open('logs/attacks.log', 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log = json.loads(line.strip())
                        logs.append(log)
                    except json.JSONDecodeError:
                        app.logger.error(f"无效的日志行: {line}")
                        continue
        except FileNotFoundError:
            app.logger.warning("日志文件不存在")

        # 准备统计数据
        stats = {
            'total_attacks': len(logs),
            'high_severity_attacks': sum(1 for log in logs if log.get('severity', 1) >= 3),
            'ssh_attacks': sum(1 for log in logs if 'SSH' in str(log.get('type', ''))),
            'ftp_attacks': sum(1 for log in logs if 'FTP' in str(log.get('type', ''))),
            'recent_attacks': [],
            'attack_types': {},
            'daily_attacks': []
        }

        # 处理最近的攻击记录
        for log in logs[-10:]:
            # 确保每个字段都有默认值
            attack = {
                'timestamp': log.get('timestamp', '未知时间'),
                'type': log.get('type', '未知类型'),
                'ip': log.get('ip', '未知IP'),
                'details': log.get('details', '无详情'),
                'severity': log.get('severity', 1),
                'blocked': log.get('blocked', False)
            }
            stats['recent_attacks'].append(attack)

        # 统计攻击类型
        for log in logs:
            attack_type = str(log.get('type', 'Unknown'))
            stats['attack_types'][attack_type] = stats['attack_types'].get(attack_type, 0) + 1

        # 统计每日攻击数量
        daily_counts = defaultdict(int)
        for log in logs:
            try:
                date = log['timestamp'].split()[0]
                daily_counts[date] += 1
            except (KeyError, IndexError):
                continue

        # 获取最近7天的数据
        today = datetime.now().date()
        dates = [(today - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
        stats['daily_attacks'] = [
            {'date': date, 'count': daily_counts.get(date, 0)}
            for date in dates
        ]

        return render_template('dashboard.html', stats=stats)

    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}\n{traceback.format_exc()}")
        # 返回空统计数据
        return render_template('dashboard.html', stats={
            'total_attacks': 0,
            'high_severity_attacks': 0,
            'ssh_attacks': 0,
            'ftp_attacks': 0,
            'recent_attacks': [],
            'attack_types': {},
            'daily_attacks': []
        })


@app.route('/logs')
def show_logs():
    """显示攻击日志页面"""
    try:
        # 获取过滤参数
        page = request.args.get('page', 1, type=int)
        attack_type = request.args.get('type', '')
        date_filter = request.args.get('date', '')
        search = request.args.get('search', '')
        per_page = 10

        # 读取日志文件
        logs = []
        with open('logs/attacks.log', 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    log = json.loads(line.strip())

                    # 应用过滤条件
                    if attack_type and log.get('type') != attack_type:
                        continue

                    if date_filter and not log.get('timestamp', '').startswith(date_filter):
                        continue

                    if search and search.lower() not in str(log).lower():
                        continue

                    # 添加默认值
                    log.setdefault('severity', 1)
                    log.setdefault('blocked', False)
                    logs.append(log)

                except json.JSONDecodeError:
                    app.logger.error(f"无效的日志行: {line}")
                    continue

        # 按时间倒序排序
        logs.sort(key=lambda x: x['timestamp'], reverse=True)

        # 计算分页
        total = len(logs)
        total_pages = (total + per_page - 1) // per_page
        start = (page - 1) * per_page
        end = start + per_page
        current_logs = logs[start:end]

        # 获取所有攻击类型（用于过滤下拉框）
        attack_types = sorted(list(set(log.get('type') for log in logs)))

        return render_template(
            'logs.html',
            logs=current_logs,
            page=page,
            total_pages=total_pages,
            attack_types=attack_types,
            current_type=attack_type,
            current_date=date_filter,
            current_search=search
        )

    except Exception as e:
        app.logger.error(f"显示日志失败: {str(e)}\n{traceback.format_exc()}")
        return render_template('error.html', error="加载日志数据失败，请查看日志获取详细信息。"), 500


@app.route('/export_logs')
def export_attack_logs():
    """导出攻击日志"""
    try:
        # 读取日志文件
        logs = []
        with open('logs/attacks.log', 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    # 处理使用单引号的JSON
                    line = line.strip().replace("'", '"')
                    if line:
                        log = json.loads(line)
                        logs.append(log)
                except json.JSONDecodeError:
                    app.logger.error(f"无效的日志行: {line}")
                    continue

        if not logs:
            raise ValueError("没有可导出的日志数据")

        # 生成CSV格式的响应
        output = "时间,攻击类型,IP地址,详情,状态\n"
        for log in logs:
            try:
                row = [
                    log.get('timestamp', ''),
                    log.get('type', ''),
                    log.get('ip', ''),
                    log.get('details', '').replace(',', ';'),  # 避免CSV分隔符冲突
                    '已拦截' if log.get('blocked', False) else '已通过'
                ]
                output += ','.join(str(item) for item in row) + '\n'
            except Exception as e:
                app.logger.error(f"处理日志行失败: {str(e)}, 日志: {log}")
                continue

        # 设置响应头，使浏览器下载文件
        response = make_response(output)
        response.headers[
            "Content-Disposition"] = f"attachment; filename=attack_logs_{datetime.now().strftime('%Y%m%d')}.csv"
        response.headers["Content-type"] = "text/csv; charset=utf-8-sig"
        return response

    except Exception as e:
        app.logger.error(f"导出日志失败: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': '导出日志失败', 'details': str(e)}), 500


@app.route("/api/dashboard/stats")
def get_dashboard_stats():
    """获取仪表板统计数据的API端点"""
    try:
        with open('logs/attacks.log', 'r', encoding='utf-8') as f:
            logs = [json.loads(line.strip()) for line in f if line.strip()]

        # 计算统计数据
        stats = {
            'attack_types': {},
            'top_attackers': {},
            'daily_attacks': []
        }

        # 统计攻击类型
        for log in logs:
            attack_type = log.get('type', 'Unknown')
            stats['attack_types'][attack_type] = stats['attack_types'].get(attack_type, 0) + 1

            # 统计攻击者
            ip = log.get('ip', 'unknown')
            stats['top_attackers'][ip] = stats['top_attackers'].get(ip, 0) + 1

        # 按攻击次数排序并只保留前10个攻击者
        stats['top_attackers'] = dict(sorted(
            stats['top_attackers'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10])

        return jsonify(stats)

    except Exception as e:
        app.logger.error(f"获取仪表板统计数据失败: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': '获取统计数据失败'}), 500


# 文件上传蜜罐
@app.route('/system/upload', methods=['GET', 'POST'])
def honeypot_upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            filename = file.filename
            # 记录文件上传尝试
            log_attack(
                type="file_upload",
                details=f"尝试上传文件: {filename}",
                blocked=True,
                ip=request.remote_addr
            )
        return jsonify({'error': '服务器错误'}), 500

    return render_template('honeypot/upload.html')


# SQL注入蜜罐
@app.route('/system/api/users')
def honeypot_users():
    username = request.args.get('username', '')
    department = request.args.get('department', '')

    # 记录查询尝试
    log_attack(
        type="sql_injection",
        details=f"查询参数: username={username}, department={department}",
        blocked=True,
        ip=request.remote_addr
    )

    return jsonify({'error': '数据库连接错误'}), 500


@app.route('/system/search')
def honeypot_search():
    return render_template('honeypot/search.html')


@app.route('/system/admin', methods=['GET'])
def honeypot_admin():
    """蜜罐管理系统登录页面"""
    return render_template('honeypot/admin.html')


@app.route('/system/login', methods=['POST'])
def honeypot_login():
    """蜜罐登录接口"""
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    ip = request.remote_addr

    # 记录登录尝试
    log_attack(
        type="unauthorized_access",
        details=f"蜜罐管理系统登录尝试 - 用户名: {username}",
        blocked=True,
        ip=ip
    )

    # 始终返回登录失败
    return jsonify({
        'error': '用户名或密码错误',
        'code': 401
    }), 401


@app.route('/system/forgot_password', methods=['GET'])
def honeypot_forgot_password():
    """蜜罐忘记密码页面"""
    return render_template('honeypot/forgot_password.html')


@app.route('/system/send_code', methods=['POST'])
def honeypot_send_code():
    """蜜罐发送验证码接口"""
    data = request.get_json()
    phone = data.get('phone', '')
    email = data.get('email', '')

    # 记录获取验证码的尝试
    log_attack(
        type="password_reset_attempt",
        details=f"尝试获取验证码 - 手机: {phone}, 邮箱: {email}",
        blocked=True,
        ip=request.remote_addr
    )

    # 返回成功响应，实际上不会发送验证码
    return jsonify({'success': True})


@app.route('/system/reset_password', methods=['POST'])
def honeypot_reset_password():
    """蜜罐重置密码接口"""
    data = request.get_json()
    username = data.get('username', '')
    email = data.get('email', '')
    phone = data.get('phone', '')
    code = data.get('code', '')

    # 记录重置密码尝试
    log_attack(
        type="password_reset_attempt",
        details=f"尝试重置密码 - 用户名: {username}, 手机: {phone}, 邮箱: {email}, 验证码: {code}",
        blocked=True,
        ip=request.remote_addr
    )

    # 返回错误信息
    return jsonify({
        'error': '验证码错误或已过期，请重新获取'
    }), 400


@app.route('/system', methods=['GET'])
def honeypot_index():
    """蜜罐系统首页"""
    # 记录访问尝试
    log_attack(
        type="system_access",
        details="访问蜜罐系统首页",
        blocked=False,
        ip=request.remote_addr
    )

    # 生成一些随机的系统状态数据
    system_stats = {
        'online_users': random.randint(100, 150),
        'system_load': random.randint(30, 60),
        'disk_usage': random.randint(65, 85),
        'alerts': random.randint(5, 15),
        'announcements': [
            {
                'title': '系统将于今晚23:00进行例行维护',
                'date': '2024-01-01'
            },
            {
                'title': '新版本V3.1.4更新说明',
                'date': '2023-12-28'
            },
            {
                'title': '关于加强系统安全性的通知',
                'date': '2023-12-25'
            },
            {
                'title': '2024年春节放假安排',
                'date': '2023-12-20'
            }
        ]
    }

    return render_template('honeypot/system_index.html', stats=system_stats)


# 蜜罐系统工具页面
@app.route('/system/tools')
def honeypot_tools():
    return render_template('honeypot/tools.html')


# 蜜罐系统诊断接口
@app.route('/system/api/diagnose', methods=['POST'])
def api_diagnose():
    """处理网络诊断请求"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()

        # 检测危险命令
        dangerous_commands = ['ls', 'cat', 'pwd', 'whoami', 'id', 'uname', 'ps', 'netstat', 'wget', 'curl', 'ping',
                              'telnet', 'ssh', 'ftp', 'nc']
        detected_commands = [cmd for cmd in dangerous_commands if cmd in target.lower()]

        if detected_commands:
            # 记录攻击日志
            log_attack(
                type="Command Injection",
                details=f"检测到命令注入 | 命令: {target} | 模式: {', '.join(detected_commands)}",
                blocked=True,
                ip=request.remote_addr
            )
            return jsonify({
                "error": "检测到恶意命令，操作已被阻止。",
                "details": f"命令: {target} | 模式: {', '.join(detected_commands)}"
            }), 403

        # 模拟诊断操作
        result = f"诊断结果: {target} 是一个有效的目标。"
        return jsonify({"result": result})

    except Exception as e:
        app.logger.error(f"诊断请求处理失败: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "诊断请求处理失败", "details": str(e)}), 500


@app.route('/system/index')
def honeypot_system_index():
    """蜜罐系统首页"""
    # 记录访问尝试
    log_attack(
        type="system_access",
        details="访问蜜罐系统后台首页",
        blocked=False,
        ip=request.remote_addr
    )

    # 生成一些随机的系统状态数据
    system_stats = {
        'cpu_usage': random.randint(30, 80),
        'memory_usage': random.randint(40, 90),
        'disk_usage': random.randint(50, 95),
        'network_traffic': random.randint(100, 1000),
        'online_users': random.randint(10, 50),
        'recent_alerts': [
            {'time': '10:05:23', 'type': '安全警告', 'content': '检测到异常登录尝试'},
            {'time': '09:58:12', 'type': '系统通知', 'content': '数据库备份完成'},
            {'time': '09:45:30', 'type': '性能警告', 'content': 'CPU使用率超过80%'},
        ]
    }

    return render_template('honeypot/system_index.html', stats=system_stats)


# 在应用启动时确保日志目录存在
ensure_log_directory()


@app.route('/system/<path:path>', methods=['GET', 'POST'])
def honeypot_system(path):
    """处理蜜罐系统的所有请求"""
    try:
        # 获取请求数据
        payload = {
            'form': dict(request.form),
            'args': dict(request.args),
            'json': request.get_json(silent=True),
            'headers': dict(request.headers),
            'path': path
        }

        # 初始化日志条目
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': 'honeypot_access',
            'ip': request.remote_addr,
            'path': f'/system/{path}',
            'method': request.method,
            'params': payload,
            'user_agent': request.headers.get('User-Agent'),
            'blocked': False,
            'severity': 2
        }

        # 检测各类攻击
        attack_detected = False
        detected_patterns = []

        # 1. 命令注入检测
        dangerous_commands = [
            'ls', 'cat', 'pwd', 'whoami', 'id', 'uname', 'ps', 'netstat',
            'wget', 'curl', 'ping', 'telnet', 'ssh', 'ftp', 'nc'
        ]

        # 检查所有输入源
        input_data = str(payload)

        # 执行检测
        for cmd in dangerous_commands:
            if cmd in input_data.lower():
                attack_detected = True
                detected_patterns.append(f"command_injection:{cmd}")
                app.logger.debug(f"检测到命令注入: {cmd}")

        # 如果检测到攻击，更新日志条目
        if attack_detected:
            log_entry.update({
                'type': 'Command Injection',
                'details': f'检测到命令注入 | 模式: {", ".join(detected_patterns)} | 输入: {input_data}',
                'blocked': True,
                'severity': 4,
                'detected_patterns': detected_patterns
            })

            # 调用通知器
            notifier.check_and_notify(log_entry)

        # 写入日志文件
        with open('logs/attacks.log', 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')

        # 如果检测到攻击，返回错误页面
        if attack_detected:
            return render_template('error.html', error="检测到恶意操作，请求已被拦截。"), 403

        # 正常返回对应页面
        if path in ['admin', 'forgot_password', 'search', 'system_index', 'tools', 'upload']:
            return render_template(f'honeypot/{path}.html')
        else:
            return render_template('error.html', error="页面不存在"), 404

    except Exception as e:
        app.logger.error(f"蜜罐系统错误: {str(e)}\n{traceback.format_exc()}")
        return render_template('error.html', error="系统暂时无法访问，请稍后重试。"), 500


def start_monitoring():
    notifier = AttackNotifier()
    monitor_attacks('logs/attacks.log', notifier)


if __name__ == "__main__":
    # 启动监控线程
    monitoring_thread = threading.Thread(target=start_monitoring)
    monitoring_thread.daemon = True
    monitoring_thread.start()

    # 启动Flask应用
    app.run(debug=True)
