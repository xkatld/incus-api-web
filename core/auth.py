from functools import wraps
from flask import request, session, redirect, url_for, jsonify, current_app
import logging

logger = logging.getLogger(__name__)

def verify_api_key_hash():
    api_key_hash_header = request.headers.get('X-API-Key-Hash')
    stored_api_key_hash = current_app.config.get('SETTINGS', {}).get('api_key_hash')

    if not api_key_hash_header:
        logger.warning(f"API认证失败: 缺少 'X-API-Key-Hash' 请求头 from {request.remote_addr}")
        return False

    if not stored_api_key_hash:
        logger.error("API认证失败: 未从数据库加载到 'api_key_hash'。请检查设置。")
        return False

    if api_key_hash_header == stored_api_key_hash:
        logger.debug(f"API密钥哈希认证成功 from {request.remote_addr}")
        return True
    else:
        logger.warning(f"API密钥哈希认证失败: 哈希值不匹配 from {request.remote_addr}")
        return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('logged_in') is not True:
            return redirect(url_for('views.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def web_or_api_authentication_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        settings = current_app.config.get('SETTINGS')
        if not settings:
            logger.error("认证失败: 设置未加载。请检查数据库和 init_db.py 运行情况。")
            if request.method == 'GET':
                 return jsonify({'status': 'error', 'message': '认证失败: 应用设置未加载。'}), 500
            else:
                 return jsonify({'status': 'error', 'message': '认证失败: 应用设置未加载。'}), 500

        is_authenticated_via_session = session.get('logged_in') is True
        is_authenticated_via_api = False

        if not is_authenticated_via_session:
            is_authenticated_via_api = verify_api_key_hash()

        if is_authenticated_via_session or is_authenticated_via_api:
            return f(*args, **kwargs)
        else:
            if request.is_json or request.headers.get('Accept') == 'application/json' or not request.accept_mimetypes.accept_html:
                 return jsonify({'status': 'error', 'message': '需要认证'}), 401
            else:
                 return redirect(url_for('views.login', next=request.url))
    return decorated_function
