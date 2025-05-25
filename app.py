from flask import Flask
from flask_socketio import SocketIO
import os
import sys
import subprocess
import logging

from config import FLASK_SECRET_KEY, DATABASE_NAME
from db_manager import load_settings_from_db, get_db_connection
from views import views
from sockets import register_socket_handlers

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = FLASK_SECRET_KEY
socketio = SocketIO(app, async_mode='threading')

def perform_initial_setup():
    logger.info("============================================")
    logger.info(" Incus Web 管理器启动检查")
    logger.info("============================================")

    if not os.path.exists(DATABASE_NAME):
        logger.error(f"错误：数据库文件 '{DATABASE_NAME}' 未找到。请运行 'python init_db.py'。")
        sys.exit(1)

    settings = load_settings_from_db()
    if not settings:
        logger.error("错误：无法从数据库加载设置。请运行 'python init_db.py'。")
        sys.exit(1)

    app.config['SETTINGS'] = settings # Store settings in app config
    logger.info(f"管理员用户名: {settings.get('admin_username', 'N/A')}")
    logger.info(f"API 密钥哈希: {settings.get('api_key_hash', 'N/A')}")

    # Check DB tables (basic)
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='containers';")
        if not cursor.fetchone():
             logger.error("错误: 数据库表 'containers' 未找到。")
             sys.exit(1)
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nat_rules';")
        if not cursor.fetchone():
             logger.error("错误: 数据库表 'nat_rules' 未找到。")
             sys.exit(1)
        logger.info("数据库表检查通过。")
    except Exception as e:
        logger.error(f"数据库检查失败: {e}")
        sys.exit(1)
    finally:
        if conn: conn.close()

    # Check commands
    commands_to_check = {
        'incus': ['incus', '--version'],
        'iptables': ['iptables', '--version'],
        'ssh': ['ssh', '-V']
    }
    for cmd_name, cmd_args in commands_to_check.items():
        try:
            subprocess.run(cmd_args, check=True, capture_output=True, text=True, timeout=10)
            logger.info(f"{cmd_name.capitalize()} 命令检查通过。")
        except FileNotFoundError:
            logger.error(f"错误: '{cmd_name}' 命令未找到。NAT 或 SSH 功能可能无法使用。")
            if cmd_name in ['incus', 'ssh']: sys.exit(1)
        except Exception as e:
            logger.warning(f"执行 '{' '.join(cmd_args)}' 时出现问题: {e}")

    logger.info("============================================")

def create_app():
    # Register Blueprint
    app.register_blueprint(views)

    # Register SocketIO handlers
    register_socket_handlers(socketio)

    return app

if __name__ == '__main__':
    perform_initial_setup()

    create_app()
    logger.info("启动 Flask-SocketIO Web 服务器...")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True, use_reloader=False)
