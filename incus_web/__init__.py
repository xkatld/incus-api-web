from flask import Flask
from flask_socketio import SocketIO
import os
import sys
import logging
from .config import Config
from .db import load_settings_from_db, init_app as init_db_app
from .services.ssl_manager import check_and_generate_ssl_cert

socketio = SocketIO()

def create_app(config_class=Config):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    init_db_app(app)
    socketio.init_app(app, async_mode='threading')

    with app.app_context():
        settings = load_settings_from_db()
        if not settings:
            logging.error("致命错误: 无法从数据库加载设置。请先运行 'python3 scripts/init_db.py'。")
            sys.exit(1)
        app.config['SETTINGS'] = settings
        use_https, ssl_context = check_and_generate_ssl_cert(app.instance_path)
        app.config['USE_HTTPS'] = use_https
        app.config['SSL_CONTEXT'] = ssl_context

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .api import api_bp
    app.register_blueprint(api_bp)

    from .main.events import register_socket_handlers
    register_socket_handlers(socketio)

    return app