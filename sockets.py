from flask_socketio import emit
from flask import request, current_app
import pexpect
import threading
import sys
import logging
import re

logger = logging.getLogger(__name__)
children = {}

def read_and_forward_ssh_output(sid, child, socketio):
    while True:
        if not child.isalive():
            logger.warning(f"SSH 进程 (SID: {sid}) 似乎已关闭。")
            try:
                socketio.emit('ssh_output', '\r\n[SSH会话似乎已中断]', room=sid)
            except Exception: pass
            break
        try:
            output = child.read_nonblocking(size=1024, timeout=0.1)
            if output:
                 socketio.emit('ssh_output', output, room=sid)
        except pexpect.TIMEOUT:
            continue
        except pexpect.EOF:
            try:
                socketio.emit('ssh_output', '\r\n[SSH会话已结束]', room=sid)
            except Exception: pass
            break
        except Exception as e:
            if isinstance(e, OSError) and e.errno == 9:
                 logger.warning(f"SSH 读取时遇到 Bad file descriptor (SID: {sid}) - 可能已断开连接。")
            else:
                 logger.error(f"读取 SSH 输出时发生错误 (SID: {sid}): {e}")
            try:
                socketio.emit('ssh_error', f'读取输出错误: {e}', room=sid)
            except Exception: pass
            break

    logger.info(f"SSH 输出线程结束 (SID: {sid})")
    child_to_remove = children.pop(sid, None)
    if child_to_remove and child_to_remove.isalive():
        try:
            child_to_remove.close(force=True)
            logger.info(f"SSH 线程确保子进程已关闭 (SID: {sid})")
        except Exception as e:
            logger.error(f"SSH 线程关闭子进程时发生错误 (SID: {sid}): {e}")

def register_socket_handlers(socketio):

    @socketio.on('connect')
    def handle_connect():
        logger.info(f"客户端连接: {request.sid}")

    @socketio.on('disconnect')
    def handle_disconnect():
        sid = request.sid
        logger.info(f"客户端断开连接: {sid}")
        child = children.pop(sid, None)
        if child and child.isalive():
            logger.info(f"正在终止 SSH 进程 (SID: {sid})")
            try:
                child.close(force=True)
            except Exception as e:
                logger.error(f"关闭 SSH 进程时发生错误 (SID: {sid}): {e}")

    @socketio.on('start_ssh')
    def handle_start_ssh(data):
        sid = request.sid
        container = data.get('container')
        ip = data.get('ip')
        cols = data.get('cols', 80)
        rows = data.get('rows', 24)

        logger.info(f"收到 SSH 启动请求 (SID: {sid}): 容器={container}, IP={ip}")

        if not ip or not (ip.startswith('10.') or ip.startswith('172.') or ip.startswith('192.168.') or re.match(r'^[a-f0-9:]+$', ip)):
            logger.warning(f"拒绝 SSH 请求 (SID: {sid}): 无效 IP 地址 {ip}")
            emit('ssh_error', f'无效的 IP 地址: {ip}', room=sid)
            return

        username = 'root'
        command = f'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {username}@{ip}'
        logger.info(f"正在执行 pexpect: {command} (SID: {sid})")

        try:
            child = pexpect.spawn(command, encoding='utf-8', timeout=10, logfile=sys.stdout)
            child.setwinsize(rows, cols)
            children[sid] = child

            thread = threading.Thread(target=read_and_forward_ssh_output, args=(sid, child, socketio))
            thread.daemon = True
            thread.start()

            emit('ssh_output', f'正在尝试连接到 {username}@{ip}...\r\n密码默认为 123456。\r\n', room=sid)

        except (pexpect.exceptions.TIMEOUT, pexpect.exceptions.EOF) as e:
            logger.error(f"SSH 连接失败 (SID: {sid}): {ip}. Error: {e}")
            emit('ssh_error', f'连接 {ip} 失败。请检查 SSH 服务和网络。', room=sid)
            children.pop(sid, None)
        except Exception as e:
            logger.error(f"启动 SSH 时发生错误 (SID: {sid}): {e}")
            emit('ssh_error', f'启动 SSH 时发生错误: {e}', room=sid)
            children.pop(sid, None)

    @socketio.on('ssh_input')
    def handle_ssh_input(data):
        sid = request.sid
        if sid in children:
            child = children[sid]
            if child.isalive():
                try:
                    child.send(data['input'])
                except Exception as e:
                    logger.error(f"发送 SSH 输入时发生错误 (SID: {sid}): {e}")
            else:
                emit('ssh_error', 'SSH 会话已关闭。', room=sid)
        else:
            emit('ssh_error', '未找到活动的 SSH 会话。', room=sid)

    @socketio.on('ssh_resize')
    def handle_ssh_resize(data):
        sid = request.sid
        if sid in children:
            child = children[sid]
            if child.isalive():
                try:
                    child.setwinsize(data['rows'], data['cols'])
                except Exception as e:
                    logger.warning(f"调整 SSH 终端大小时发生错误 (SID: {sid}): {e}")
