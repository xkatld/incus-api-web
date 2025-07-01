from functools import wraps
from flask import request, session, redirect, url_for, jsonify, current_app
import logging

logger = logging.getLogger(__name__)

def verify_api_key_hash():
    api_key_hash_header = request.headers.get('X-API-Key-Hash')
    stored_api_key_hash = current_app.config.get('SETTINGS', {}).get('api_key_hash')
    if not api_key_hash_header:
        return False
    if not stored_api_key_hash:
        return False
    return api_key_hash_header == stored_api_key_hash

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('main.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def web_or_api_authentication_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('logged_in'):
            return f(*args, **kwargs)
        if verify_api_key_hash():
            return f(*args, **kwargs)
        if request.is_json or request.headers.get('Accept') == 'application/json':
             return jsonify({'status': 'error', 'message': '需要认证'}), 401
        else:
             return redirect(url_for('main.login', next=request.url))
    return decorated_function

def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not verify_api_key_hash():
            return {'状态': '错误', '消息': '需要有效的 API 密钥哈希 (X-API-Key-Hash)。'}, 401
        return f(*args, **kwargs)
    return decorated