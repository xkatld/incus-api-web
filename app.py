import os
import sys
import logging
from incus_web import create_app, socketio

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = create_app()

if __name__ == '__main__':
    use_https = app.config.get("USE_HTTPS", False)
    ssl_context = app.config.get("SSL_CONTEXT")
    host = '0.0.0.0'
    port = 5000

    logger.info("启动 Flask-SocketIO Web 服务器...")
    if use_https and ssl_context:
        logger.info(f"将在 HTTPS 模式下运行 (https://{host}:{port})。")
        try:
            socketio.run(app, host=host, port=port, ssl_context=ssl_context, allow_unsafe_werkzeug=True, use_reloader=False)
        except Exception as e:
            logger.error(f"启动 HTTPS 服务器失败: {e}")
            logger.warning("回退到 HTTP 模式运行。")
            socketio.run(app, host=host, port=port, allow_unsafe_werkzeug=True, use_reloader=False)
    else:
        logger.warning(f"将在 HTTP 模式下运行 (http://{host}:{port})。")
        socketio.run(app, host=host, port=port, allow_unsafe_werkzeug=True, use_reloader=False)