from flask_socketio import emit
from flask import request
import pexpect
import threading
import sys
import logging
import re

logger = logging.getLogger(__name__)
children = {}

def read_and_forward_ssh_output(sid, child, socketio):
    while child.isalive():
        try:
            output = child.read_nonblocking(size=1024, timeout=0.1)
            if output:
                socketio.emit('ssh_output', output.decode('utf-8', 'replace'), room=sid)
        except pexpect.TIMEOUT:
            continue
        except pexpect.EOF:
            socketio.emit('ssh_output', '\r\n[SSH会话已结束]', room=sid)
            break
        except Exception as e:
            logger.error(f"读取 SSH 输出时发生错误 (SID: {sid}): {e}")
            socketio.emit('ssh_error', f'读取输出错误: {e}', room=sid)
            break
    
    child_to_remove = children.pop(sid, None)
    if child_to_remove and child_to_remove.isalive():
        child_to_remove.close(force=True)

def register_socket_handlers(socketio):
    @socketio.on('disconnect')
    def handle_disconnect():
        sid = request.sid
        child = children.pop(sid, None)
        if child and child.isalive():
            child.close(force=True)

    @socketio.on('start_ssh')
    def handle_start_ssh(data):
        sid = request.sid
        ip = data.get('ip')

        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if not ip or not ip_pattern.match(ip):
            emit('ssh_error', '错误: 无效的IP地址格式', room=sid)
            return

        command = f'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@{ip}'
        try:
            child = pexpect.spawn(command, encoding='utf-8', timeout=10)
            child.setwinsize(data.get('rows', 24), data.get('cols', 80))
            children[sid] = child
            thread = threading.Thread(target=read_and_forward_ssh_output, args=(sid, child, socketio))
            thread.daemon = True
            thread.start()
            emit('ssh_output', f'正在尝试连接到 root@{ip}...\r\n', room=sid)
        except Exception as e:
            emit('ssh_error', f'启动 SSH 时发生错误: {e}', room=sid)
            children.pop(sid, None)

    @socketio.on('ssh_input')
    def handle_ssh_input(data):
        sid = request.sid
        if sid in children and children[sid].isalive():
            children[sid].send(data['input'])

    @socketio.on('ssh_resize')
    def handle_ssh_resize(data):
        sid = request.sid
        if sid in children and children[sid].isalive():
            children[sid].setwinsize(data['rows'], data['cols'])