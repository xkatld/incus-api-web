from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, current_app
import hashlib
import time
import logging
import shlex
from . import main
from ..auth import login_required, web_or_api_authentication_required
from ..services import incus_commands, nat_manager, nginx_manager
from ..db import query_db, sync_container_to_db, remove_container_from_db, get_nat_rules_for_container, check_nat_rule_exists_in_db, add_nat_rule_to_db, get_nat_rule_by_id, remove_nat_rule_from_db, get_quick_commands, add_quick_command, remove_quick_command_from_db, add_reverse_proxy_rule_to_db, get_reverse_proxy_rules_for_container, get_reverse_proxy_rule_by_id, remove_reverse_proxy_rule_from_db

logger = logging.getLogger(__name__)

def _get_primary_ip(network_info):
    if not network_info:
        return 'N/A'
    
    if 'eth0' in network_info and network_info['eth0'].get('addresses'):
        for addr in network_info['eth0']['addresses']:
            if addr.get('family') == 'inet' and addr.get('scope') == 'global':
                return addr.get('address', '').split('/')[0]

    for iface in network_info.values():
        if iface.get('addresses'):
            for addr in iface['addresses']:
                if addr.get('family') == 'inet' and addr.get('scope') == 'global':
                    return addr.get('address', '').split('/')[0]
                    
    return 'N/A'

@main.route('/login', methods=['GET', 'POST'])
def login():
    SETTINGS = current_app.config.get('SETTINGS')
    login_context = {'login_error': None, 'session': session, 'request': request}
    if not SETTINGS or not SETTINGS.get('admin_username') or not SETTINGS.get('admin_password_hash'):
        login_context['login_error'] = "应用未正确配置，请联系管理员。"
        return render_template('index.html', **login_context), 500
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == SETTINGS['admin_username'] and hashlib.sha256(password.encode('utf-8')).hexdigest() == SETTINGS['admin_password_hash']:
            session['logged_in'] = True
            next_url = request.form.get('next')
            return redirect(next_url or url_for('main.index'))
        else:
            login_context['login_error'] = "用户名或密码错误。"
    return render_template('index.html', **login_context)

@main.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('main.login'))

@main.route('/')
@login_required
def index():
    success_list, containers_data = incus_commands.run_incus_command(['list', '--format', 'json'])
    listed_containers = []
    if success_list:
        incus_container_names = {item['name'] for item in containers_data}
        for item in containers_data:
            network_info = item.get('state', {}).get('network', {})
            ip_address = _get_primary_ip(network_info)
            container_info = {
                'name': item['name'], 'status': item.get('status', '未知'),
                'image_source': item.get('config', {}).get('image.description', 'N/A'), 'ip': ip_address,
                'created_at': item.get('created_at'),
            }
            listed_containers.append(container_info)
            sync_container_to_db(item['name'], container_info['image_source'], container_info['status'], container_info['created_at'])
        db_names = {row['incus_name'] for row in query_db('SELECT incus_name FROM containers')}
        for name_to_remove in db_names - incus_container_names:
            remove_container_from_db(name_to_remove)
    
    success_img, images_data = incus_commands.run_incus_command(['image', 'list', '--format', 'json'])
    available_images = [{'name': img.get('aliases', [{}])[0].get('name'), 'description': f"{img.get('aliases', [{}])[0].get('name')} ({img.get('properties', {}).get('description', 'N/A')})"} for img in images_data] if success_img else []

    success_storage, storage_data = incus_commands.run_incus_command(['storage', 'list', '--format', 'json'])
    available_pools = [pool['name'] for pool in storage_data] if success_storage else []

    return render_template('index.html', containers=listed_containers, images=available_images, available_pools=available_pools, session=session, request=request)

@main.route('/container/create', methods=['POST'])
@web_or_api_authentication_required
def create_container():
    data = request.form
    name, image = data.get('name'), data.get('image')
    if not name or not image:
        return jsonify({'status': 'error', 'message': '容器名称和镜像不能为空'}), 400
    if query_db('SELECT 1 FROM containers WHERE incus_name = ?', [name], one=True):
        return jsonify({'status': 'error', 'message': f'名称为 "{name}" 的容器已存在。'}), 409
    
    command = ['launch', image, name]

    try:
        if data.get('storage_pool'):
            command.extend(['-s', data['storage_pool']])
        if data.get('cpu_cores'):
            command.extend(['-c', f'limits.cpu={int(data["cpu_cores"])}'])
        if data.get('cpu_allowance'):
            allowance = int(data["cpu_allowance"])
            if not 1 <= allowance <= 100: raise ValueError("CPU aallowance must be between 1-100")
            command.extend(['-c', f'limits.cpu.allowance={allowance}%'])
        if data.get('memory_mb'):
            command.extend(['-c', f'limits.memory={int(data["memory_mb"])}MB'])
        if data.get('disk_gb'):
            command.extend(['-d', f'root,size={int(data["disk_gb"])}GB'])
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'CPU、内存或磁盘参数必须是有效的正整数。'}), 400

    if data.get('security_nesting') == 'on':
        command.extend(['-c', 'security.nesting=true'])
    
    success, output = incus_commands.run_incus_command(command, parse_json=False, timeout=180)
    if success:
        time.sleep(3)
        _, list_output = incus_commands.run_incus_command(['list', name, '--format', 'json'])
        if list_output:
            sync_container_to_db(name, list_output[0].get('config',{}).get('image.description', image), list_output[0].get('status', 'Pending'), list_output[0].get('created_at'))
        return jsonify({'status': 'success', 'message': f'容器 {name} 创建操作已提交。'})
    
    logger.error(f"创建容器 {name} 失败: {output}")
    return jsonify({'status': 'error', 'message': f'创建容器 {name} 失败，请检查日志。'}), 500

@main.route('/container/<name>/action', methods=['POST'])
@web_or_api_authentication_required
def container_action(name):
    action = request.form.get('action')
    if action == 'delete':
        _, rules = get_nat_rules_for_container(name)
        for rule in rules:
            nat_manager.perform_iptables_delete_for_rule(rule)
            remove_nat_rule_from_db(rule['id'])
        success, output = incus_commands.run_incus_command(['delete', name, '--force'], parse_json=False)
        if success:
            remove_container_from_db(name)
            return jsonify({'status': 'success', 'message': f'容器 {name} 已删除。'})
        logger.error(f"删除容器 {name} 失败: {output}")
        return jsonify({'status': 'error', 'message': f'删除容器 {name} 失败，请检查日志。'}), 500

    commands = {'start': ['start', name], 'stop': ['stop', name, '--force'], 'restart': ['restart', name, '--force']}
    if action not in commands:
        return jsonify({'status': 'error', 'message': '无效的操作'}), 400
    
    success, output = incus_commands.run_incus_command(commands[action], parse_json=False)
    if success:
        time.sleep(2)
        _, list_output = incus_commands.run_incus_command(['list', name, '--format', 'json'])
        if list_output:
            sync_container_to_db(name, list_output[0].get('config', {}).get('image.description', 'N/A'), list_output[0].get('status', '未知'), list_output[0].get('created_at'))
        return jsonify({'status': 'success', 'message': f'容器 {name} {action} 成功。'})
    
    logger.error(f"容器 {name} {action} 失败: {output}")
    return jsonify({'status': 'error', 'message': f'容器 {name} {action} 失败，请检查日志。'}), 500

@main.route('/container/<name>/exec', methods=['POST'])
@web_or_api_authentication_required
def exec_command_in_container(name):
    command_to_exec = request.form.get('command')
    if not command_to_exec:
        return jsonify({'status': 'error', 'message': '命令不能为空'}), 400
    
    safe_command = shlex.quote(command_to_exec)
    command_parts = ['exec', name, '--', 'bash', '-c', safe_command]
    
    success, output = incus_commands.run_incus_command(command_parts, parse_json=False, timeout=300)
    if not success:
        logger.error(f"在容器 {name} 中执行命令失败: {output}")
        return jsonify({'status': 'error', 'output': '命令执行失败，请查看日志。'}), 500
    return jsonify({'status': 'success', 'output': output}), 200

@main.route('/container/<name>/info')
@web_or_api_authentication_required
def container_info(name):
    info, error = incus_commands.get_container_raw_info(name)
    if info:
        return jsonify(info)
    logger.warning(f"获取容器 {name} 信息失败: {error}")
    return jsonify({'status': 'NotFound', 'message': "无法找到容器信息。"}), 404

@main.route('/container/<name>/add_nat_rule', methods=['POST'])
@web_or_api_authentication_required
def add_nat_rule_route(name):
    host_port, container_port, protocol = request.form.get('host_port'), request.form.get('container_port'), request.form.get('protocol')
    _, exists = check_nat_rule_exists_in_db(name, host_port, protocol)
    if exists:
        return jsonify({'status': 'warning', 'message': '规则已存在'}), 200
    info, error = incus_commands.get_container_raw_info(name)
    if not info or info.get('status') != 'Running' or not info.get('ip') or info.get('ip') == 'N/A':
        return jsonify({'status': 'error', 'message': '无法获取容器IP或容器未运行'}), 400
    success_ipt, output = nat_manager.add_iptables_rule(info['ip'], host_port, container_port, protocol)
    if success_ipt:
        rule_details = {'container_name': name, 'host_port': host_port, 'container_port': container_port, 'protocol': protocol, 'ip_at_creation': info['ip']}
        _, rule_id = add_nat_rule_to_db(rule_details)
        return jsonify({'status': 'success', 'message': 'NAT 规则添加成功。', 'rule_id': rule_id})
    logger.error(f"为容器 {name} 添加NAT规则失败: {output}")
    return jsonify({'status': 'error', 'message': '添加 NAT 规则失败，请检查日志。'}), 500

@main.route('/container/<name>/nat_rules', methods=['GET'])
@web_or_api_authentication_required
def list_nat_rules(name):
    _, rules = get_nat_rules_for_container(name)
    return jsonify({'status': 'success', 'rules': rules})

@main.route('/container/nat_rule/<int:rule_id>', methods=['DELETE'])
@web_or_api_authentication_required
def delete_nat_rule(rule_id):
    _, rule = get_nat_rule_by_id(rule_id)
    if not rule:
        return jsonify({'status': 'warning', 'message': '规则记录未找到'}), 200
    success_ipt, output, is_bad = nat_manager.perform_iptables_delete_for_rule(rule)
    if success_ipt or is_bad:
        remove_nat_rule_from_db(rule_id)
        return jsonify({'status': 'success', 'message': 'NAT 规则已删除。'})
    logger.error(f"删除NAT规则 {rule_id} 失败: {output}")
    return jsonify({'status': 'error', 'message': '删除 NAT 规则失败，请检查日志。'}), 500

@main.route('/quick_commands', methods=['GET'])
@web_or_api_authentication_required
def list_quick_commands():
    _, commands = get_quick_commands()
    return jsonify({'status': 'success', 'commands': commands})

@main.route('/quick_commands/add', methods=['POST'])
@web_or_api_authentication_required
def add_quick_command_route():
    name, command = request.form.get('name'), request.form.get('command')
    success, result = add_quick_command(name, command)
    if success:
        return jsonify({'status': 'success', 'id': result})
    return jsonify({'status': 'error', 'message': result}), 409

@main.route('/quick_commands/delete/<int:command_id>', methods=['DELETE'])
@web_or_api_authentication_required
def delete_quick_command_route(command_id):
    success, message = remove_quick_command_from_db(command_id)
    if success:
        return jsonify({'status': 'success', 'message': message})
    return jsonify({'status': 'error', 'message': message}), 500

@main.route('/container/<name>/add_reverse_proxy', methods=['POST'])
@web_or_api_authentication_required
def add_reverse_proxy_route(name):
    domain, container_port = request.form.get('domain'), request.form.get('container_port')
    info, _ = incus_commands.get_container_raw_info(name)
    if not info or info.get('status') != 'Running' or not info.get('ip') or info.get('ip') == 'N/A':
        return jsonify({'status': 'error', 'message': '容器未运行或无IP'}), 400
    success_nginx, msg_nginx = nginx_manager.create_reverse_proxy(domain, info['ip'], container_port)
    if success_nginx:
        _, rule_id = add_reverse_proxy_rule_to_db(name, domain, container_port)
        return jsonify({'status': 'success', 'message': '反向代理规则添加成功。', 'rule_id': rule_id})
    logger.error(f"为容器 {name} 添加反向代理失败: {msg_nginx}")
    return jsonify({'status': 'error', 'message': f'添加反向代理失败，请检查日志。'}), 500

@main.route('/container/<name>/reverse_proxy_rules', methods=['GET'])
@web_or_api_authentication_required
def list_reverse_proxy_rules(name):
    _, rules = get_reverse_proxy_rules_for_container(name)
    return jsonify({'status': 'success', 'rules': rules})

@main.route('/container/reverse_proxy_rule/<int:rule_id>', methods=['DELETE'])
@web_or_api_authentication_required
def delete_reverse_proxy_rule(rule_id):
    _, rule = get_reverse_proxy_rule_by_id(rule_id)
    if not rule:
        return jsonify({'status': 'warning', 'message': '规则记录未找到'}), 200
    success_nginx, msg_nginx = nginx_manager.delete_reverse_proxy(rule['domain'])
    if success_nginx:
        remove_reverse_proxy_rule_from_db(rule_id)
        return jsonify({'status': 'success', 'message': '反向代理规则已删除。'})
    logger.error(f"删除反向代理规则 {rule_id} 失败: {msg_nginx}")
    return jsonify({'status': 'error', 'message': '删除反向代理失败，请检查日志。'}), 500