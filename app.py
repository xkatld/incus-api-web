from flask import Flask
from flask_socketio import SocketIO
import os
import sys
import subprocess
import logging
import datetime
from ipaddress import ip_address

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

from config import FLASK_SECRET_KEY, DATABASE_NAME
from db_manager import load_settings_from_db, get_db_connection
from views import views
from sockets import register_socket_handlers

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = FLASK_SECRET_KEY
socketio = SocketIO(app, async_mode='threading')

CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

def generate_self_signed_cert():
    if not CRYPTOGRAPHY_AVAILABLE:
        logger.warning("缺少 'cryptography' 库，无法生成 SSL 证书。将在 HTTP 模式下运行。请运行 'pip install cryptography'。")
        return False

    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        logger.info(f"SSL 证书 '{CERT_FILE}' 和密钥 '{KEY_FILE}' 已存在，跳过生成。")
        return True

    logger.info(f"正在生成自签名 SSL 证书 '{CERT_FILE}' 和密钥 '{KEY_FILE}'...")

    try:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Beijing"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Beijing"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"IncusWebSelfSigned"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),
                x509.IPAddress(ip_address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(key, hashes.SHA256(), default_backend())

        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        logger.info("自签名 SSL 证书和密钥生成成功。")
        return True
    except Exception as e:
        logger.error(f"生成自签名 SSL 证书时发生错误: {e}")
        if os.path.exists(KEY_FILE): os.remove(KEY_FILE)
        if os.path.exists(CERT_FILE): os.remove(CERT_FILE)
        return False


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

    app.config['SETTINGS'] = settings
    logger.info(f"管理员用户名: {settings.get('admin_username', 'N/A')}")
    logger.info(f"API 密钥哈希: {settings.get('api_key_hash', 'N/A')}")

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
    app.register_blueprint(views)
    register_socket_handlers(socketio)
    return app

if __name__ == '__main__':
    perform_initial_setup()
    ssl_context_tuple = None
    if generate_self_signed_cert():
        ssl_context_tuple = (CERT_FILE, KEY_FILE)

    create_app()
    logger.info("启动 Flask-SocketIO Web 服务器...")

    if ssl_context_tuple:
        logger.info(f"将在 HTTPS 模式下运行 (https://0.0.0.0:5000)。")
        try:
            # 修改这里：使用 ssl_context 而不是 certfile/keyfile
            socketio.run(app, debug=True, host='0.0.0.0', port=5000,
                         allow_unsafe_werkzeug=True, use_reloader=False,
                         ssl_context=ssl_context_tuple)
        except TypeError as e:
             logger.error(f"启动 HTTPS 服务器失败: {e}")
             logger.warning("似乎您的 Flask/Werkzeug 版本与 Flask-SocketIO 的 SSL 参数不兼容或存在问题。")
             logger.warning("请尝试更新库: pip install --upgrade Flask Flask-SocketIO Werkzeug python-socketio python-engineio")
             logger.warning("回退到 HTTP 模式运行。")
             socketio.run(app, debug=True, host='0.0.0.0', port=5000,
                          allow_unsafe_werkzeug=True, use_reloader=False)
        except Exception as e:
             logger.error(f"启动 HTTPS 服务器失败: {e}")
             logger.warning("回退到 HTTP 模式运行。")
             socketio.run(app, debug=True, host='0.0.0.0', port=5000,
                          allow_unsafe_werkzeug=True, use_reloader=False)

    else:
        logger.warning("将在 HTTP 模式下运行 (http://0.0.0.0:5000)。")
        socketio.run(app, debug=True, host='0.0.0.0', port=5000,
                     allow_unsafe_werkzeug=True, use_reloader=False)
