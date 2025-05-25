from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, current_app
import hashlib
import time
import shlex
import logging

from auth import login_required, web_or_api_authentication_required
from utils import run_incus_command, run_command
from db_manager import (
    query_db, sync_container_to_db, remove_container_from_db,
    get_nat_rules_for_container, check_nat_rule_exists_in_db,
    add_nat_rule_to_db, get_nat_rule_by_id, remove_nat_rule_from_db,
    cleanup_orphaned_nat_rules_in_db
)
from incus_api import get_container_raw_info
from nat_manager import perform_iptables_delete_for_rule

views = Blueprint('views', __name__)
logger = logging.getLogger(__name__)

@views.route('/login', methods=['GET', 'POST'])
def login():
    SETTINGS = current_app.config.get('SETTINGS')

    login_context = {
        'login_form': True,
        'containers': [],
        'images': [],
        'incus_error': (False, None),
        'image_error': (False, None),
        'storage_error': (False, None),
        'available_pools': [],
        'login_error': None,
        'session': session, 
        'request': request
    }

    if not SETTINGS:
        login_context['incus_error'] = (True, "应用设置未加载。请检查数据库和 init_db.py 运行情况。")
        return render_template('index.html', **login_context), 500

    admin_username = SETTINGS.get('admin_username')
    admin_password_hash = SETTINGS.get('admin_password_hash')

    if not admin_username or not admin_password_hash:
        login_context['incus_error'] = (True, "数据库中缺少管理员账号或密码哈希设置。请运行 init_db.py。")
        return render_template('index.html', **login_context), 500

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == admin_username and hashlib.sha256(password.encode('utf-8')).hexdigest() == admin_password_hash:
            session['logged_in'] = True
            logger.info(f"用户 '{username}' 登录成功。")
            next_url = request.args.get('next')
            return redirect(next_url or url_for('views.index'))
        else:
            logger.warning(f"用户 '{username}' 登录失败。")
            login_context['login_error'] = "用户名或密码错误。"
            return render_template('index.html', **login_context)
            
    return render_template('index.html', **login_context)

@views.route('/logout')
def logout():
    session.pop('logged_in', None)
    logger.info("用户已退出登录。")
    return redirect(url_for('views.login')) # Redirect to login after logout

@views.route('/')
@login_required
def index():
    SETTINGS = current_app.config.get('SETTINGS')
    if not SETTINGS:
        return render_template('index.html', incus_error=(True, "应用设置未加载。"), containers=[], images=[]), 500

    success_list, containers_data = run_incus_command(['list', '--format', 'json'])
    listed_containers = []
    db_containers_dict = {}
    incus_error = False
    incus_error_message = None

    try:
        db_containers_dict = {row['incus_name']: dict(row) for row in query_db('SELECT * FROM containers')}
    except Exception as e:
        logger.error(f"数据库错误: {e}")
        incus_error = True
        incus_error_message = f"数据库错误： {e}"
        return render_template('index.html', containers=[], images=[], incus_error=(incus_error, incus_error_message), image_error=(True, "无法加载可用镜像列表."), available_pools=[], storage_error=(True, "无法加载存储池列表."))

    incus_container_names_set = set()

    if not success_list:
        incus_error = True
        incus_error_message = containers_data
        logger.warning(f"无法从 Incus 获取容器列表 ({incus_error_message})，尝试从数据库加载。")
        for name, data in db_containers_dict.items():
            listed_containers.append({
                'name': name, 'status': data.get('status', '未知 (DB)'),
                'image_source': data.get('image_source', 'N/A (DB)'), 'ip': 'N/A (DB)',
                'created_at': data.get('created_at', 'N/A (DB)')
            })
    elif isinstance(containers_data, list):
        for item in containers_data:
            if not isinstance(item, dict) or 'name' not in item: continue
            item_name = item['name']
            incus_container_names_set.add(item_name)
            image_source = item.get('config', {}).get('image.description', 'N/A')
            created_at_str = item.get('created_at')
            ip_address = 'N/A'
            network_info = item.get('state', {}).get('network', {})
            if network_info:
                for iface_data in network_info.values():
                    if isinstance(iface_data, dict):
                        for addr_entry in iface_data.get('addresses', []):
                            if addr_entry.get('family') == 'inet' and addr_entry.get('scope') == 'global':
                                ip_address = addr_entry.get('address', 'N/A').split('/')[0]
                                break
                    if ip_address != 'N/A': break
            
            container_info = {
                'name': item_name, 'status': item.get('status', '未知'),
                'image_source': image_source, 'ip': ip_address,
                'created_at': created_at_str,
            }
            listed_containers.append(container_info)
            sync_container_to_db(item_name, image_source, item.get('status', '未知'), created_at_str)

        current_db_names = {row['incus_name'] for row in query_db('SELECT incus_name FROM containers')}
        vanished_names = [db_name for db_name in current_db_names if db_name not in incus_container_names_set]
        for db_name in vanished_names:
            remove_container_from_db(db_name)
            logger.info(f"移除数据库中不存在的容器: {db_name}")
        cleanup_orphaned_nat_rules_in_db(incus_container_names_set)
    else:
        incus_error = True
        incus_error_message = f"Incus list 返回了未知数据格式。"
        logger.error(incus_error_message)
        for name, data in db_containers_dict.items():
            listed_containers.append({
                'name': name, 'status': data.get('status', '未知 (DB)'),
                'image_source': data.get('image_source', 'N/A (DB)'), 'ip': 'N/A (DB)',
                'created_at': data.get('created_at', 'N/A (DB)')
            })

    success_img, images_data = run_incus_command(['image', 'list', '--format', 'json'])
    available_images = []
    image_error_flag = not success_img
    image_error_msg = images_data if not success_img else None
    if success_img and isinstance(images_data, list):
        for img in images_data:
            alias = (img.get('aliases') or [{}])[0].get('name', img.get('fingerprint', 'unknown')[:12])
            desc = img.get('properties', {}).get('description', 'N/A')
            available_images.append({'name': alias, 'description': f"{alias} ({desc})"})
    else:
        image_error_msg = images_data if not success_img else 'Incus 返回了无效的镜像数据格式。'

    success_storage, storage_data = run_incus_command(['storage', 'list', '--format', 'json'])
    available_pools = []
    storage_error_flag = not success_storage
    storage_error_msg = storage_data if not success_storage else None
    if success_storage and isinstance(storage_data, list):
        available_pools = [pool['name'] for pool in storage_data if 'name' in pool]
    else:
        storage_error_msg = storage_data if not success_storage else "获取存储池列表失败或格式无效。"

    return render_template('index.html',
                           containers=listed_containers, images=available_images,
                           incus_error=(incus_error, incus_error_message),
                           image_error=(image_error_flag, image_error_msg),
                           available_pools=available_pools,
                           storage_error=(storage_error_flag, storage_error_msg),
                           session=session, # Pass session explicitly
                           request=request) # Pass request explicitly


# ... (其他路由保持不变) ...

@views.route('/container/create', methods=['POST'])
@web_or_api_authentication_required
def create_container():
    name = request.form.get('name')
    image = request.form.get('image')
    cpu_cores = request.form.get('cpu_cores')
    cpu_allowance = request.form.get('cpu_allowance')
    memory_mb = request.form.get('memory_mb')
    disk_gb = request.form.get('disk_gb')
    storage_pool = request.form.get('storage_pool')
    swap_enabled = request.form.get('swap_enabled')
    security_nesting = request.form.get('security_nesting')

    if not name or not image:
        return jsonify({'status': 'error', 'message': '容器名称和镜像不能为空'}), 400

    if query_db('SELECT 1 FROM containers WHERE incus_name = ?', [name], one=True):
        return jsonify({'status': 'error', 'message': f'名称为 "{name}" 的容器已存在。'}), 409

    command = ['launch', image, name]
    if storage_pool: command.extend(['-s', storage_pool])
    try:
        if cpu_cores: command.extend(['-c', f'limits.cpu={int(cpu_cores)}'])
        if cpu_allowance: command.extend(['-c', f'limits.cpu.allowance={int(cpu_allowance)}%'])
        if memory_mb: command.extend(['-c', f'limits.memory={int(memory_mb)}MB'])
        if disk_gb: command.extend(['-d', f'root,size={int(disk_gb)}GB'])
        command.extend(['-c', f'limits.memory.swap={"true" if swap_enabled == "on" else "false"}'])
        if security_nesting == 'on': command.extend(['-c', 'security.nesting=true'])
    except ValueError:
        return jsonify({'status': 'error', 'message': '资源限制参数必须是有效的数字。'}), 400

    success, output = run_incus_command(command, parse_json=False, timeout=180)

    if success:
        time.sleep(5)
        _, list_output = run_incus_command(['list', name, '--format', 'json'])
        if isinstance(list_output, list) and list_output:
            c_data = list_output[0]
            sync_container_to_db(name, c_data.get('config',{}).get('image.description', image), c_data.get('status', 'Pending'), c_data.get('created_at'))
        else:
             sync_container_to_db(name, image, 'Pending', None)
        return jsonify({'status': 'success', 'message': f'容器 {name} 创建操作已提交。'}), 200
    else:
        return jsonify({'status': 'error', 'message': f'创建容器 {name} 失败: {output}'}), 500


@views.route('/container/<name>/action', methods=['POST'])
@web_or_api_authentication_required
def container_action(name):
    action = request.form.get('action')
    commands = {'start': ['start', name], 'stop': ['stop', name, '--force'], 'restart': ['restart', name, '--force']}

    if action == 'delete':
        success_db, rules = get_nat_rules_for_container(name)
        if not success_db: return jsonify({'status': 'error', 'message': f'获取NAT规则失败: {rules}'}), 500
        
        failed_deletions = []
        warning_deletions = []
        for rule in rules:
            success_ipt, ipt_msg, is_bad = perform_iptables_delete_for_rule(rule)
            if not success_ipt:
                if is_bad: warning_deletions.append(ipt_msg)
                else: failed_deletions.append(ipt_msg)
            remove_nat_rule_from_db(rule['id']) # Always try to remove DB record

        if failed_deletions:
            return jsonify({'status': 'error', 'message': f"删除部分NAT规则失败: {'; '.join(failed_deletions)}"}), 500

        success_incus, incus_output = run_incus_command(['delete', name, '--force'], parse_json=False, timeout=120)
        if success_incus:
            remove_container_from_db(name)
            msg = f'容器 {name} 已删除。'
            if warning_deletions: msg += " 注意: 部分iptables规则未找到。"
            return jsonify({'status': 'success', 'message': msg}), 200
        else:
            return jsonify({'status': 'error', 'message': f'删除容器 {name} 失败: {incus_output}'}), 500

    if action not in commands:
        return jsonify({'status': 'error', 'message': '无效的操作'}), 400

    success, output = run_incus_command(commands[action], parse_json=False, timeout=120)

    if success:
        time.sleep(3)
        _, list_output = run_incus_command(['list', name, '--format', 'json'])
        new_status = '未知'
        if isinstance(list_output, list) and list_output:
            new_status = list_output[0].get('status', '未知')
            sync_container_to_db(name, list_output[0].get('config', {}).get('image.description', 'N/A'), new_status, list_output[0].get('created_at'))
        return jsonify({'status': 'success', 'message': f'容器 {name} {action} 成功，新状态: {new_status}。'}), 200
    else:
        return jsonify({'status': 'error', 'message': f'容器 {name} {action} 失败: {output}'}), 500

@views.route('/container/<name>/exec', methods=['POST'])
@web_or_api_authentication_required
def exec_command_in_container(name):
    command_to_exec = request.form.get('command')
    if not command_to_exec:
        return jsonify({'status': 'error', 'message': '命令不能为空'}), 400
    try:
        command_parts = shlex.split(command_to_exec)
    except ValueError as e:
        return jsonify({'status': 'error', 'message': f'无效命令格式: {e}'}), 400

    success, output = run_incus_command(['exec', name, '--'] + command_parts, parse_json=False, timeout=120)
    status_code = 200 if success else 500
    return jsonify({'status': 'success' if success else 'error', 'output': output}), status_code

@views.route('/container/<name>/info')
@web_or_api_authentication_required
def container_info(name):
    info, error = get_container_raw_info(name)
    if info:
        return jsonify(info), 200
    else:
        return jsonify({'status': 'NotFound', 'message': error}), 404

@views.route('/container/<name>/add_nat_rule', methods=['POST'])
@web_or_api_authentication_required
def add_nat_rule_route(name):
    host_port_str = request.form.get('host_port')
    container_port_str = request.form.get('container_port')
    protocol = request.form.get('protocol')

    try:
        host_port = int(host_port_str)
        container_port = int(container_port_str)
        if not (1 <= host_port <= 65535 and 1 <= container_port <= 65535):
            raise ValueError("端口号必须在 1 到 65535 之间。")
    except (ValueError, TypeError):
         return jsonify({'status': 'error', 'message': '端口号无效'}), 400

    if protocol not in ['tcp', 'udp']:
         return jsonify({'status': 'error', 'message': '协议必须是 tcp 或 udp'}), 400

    db_ok, exists = check_nat_rule_exists_in_db(name, host_port, protocol)
    if not db_ok: return jsonify({'status': 'error', 'message': f'检查规则失败: {exists}'}), 500
    if exists: return jsonify({'status': 'warning', 'message': '规则已存在'}), 200

    info, error = get_container_raw_info(name)
    if not info: return jsonify({'status': 'error', 'message': f'获取容器信息失败: {error}'}), 404
    if info.get('status') != 'Running': return jsonify({'status': 'error', 'message': '容器未运行'}), 400
    container_ip = info.get('ip')
    if not container_ip or container_ip == 'N/A': return jsonify({'status': 'error', 'message': '无法获取容器 IP'}), 500

    iptables_cmd = ['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', protocol, '--dport', str(host_port), '-j', 'DNAT', '--to-destination', f'{container_ip}:{container_port}']
    success_ipt, output = run_command(iptables_cmd, parse_json=False)

    if success_ipt:
        rule_details = {'container_name': name, 'host_port': host_port, 'container_port': container_port, 'protocol': protocol, 'ip_at_creation': container_ip}
        db_add_ok, db_res = add_nat_rule_to_db(rule_details)
        if db_add_ok:
            return jsonify({'status': 'success', 'message': 'NAT 规则添加成功。', 'rule_id': db_res}), 200
        else:
            return jsonify({'status': 'warning', 'message': f'iptables 成功，但数据库记录失败: {db_res}'}), 200
    else:
        return jsonify({'status': 'error', 'message': f'添加 NAT 规则失败: {output}'}), 500

@views.route('/container/<name>/nat_rules', methods=['GET'])
@web_or_api_authentication_required
def list_nat_rules(name):
    success, rules = get_nat_rules_for_container(name)
    if success:
        return jsonify({'status': 'success', 'rules': rules}), 200
    else:
        return jsonify({'status': 'error', 'message': rules}), 500

@views.route('/container/nat_rule/<int:rule_id>', methods=['DELETE'])
@web_or_api_authentication_required
def delete_nat_rule(rule_id):
    success_db, rule = get_nat_rule_by_id(rule_id)
    if not success_db: return jsonify({'status': 'error', 'message': f'获取规则失败: {rule}'}), 500
    if not rule: return jsonify({'status': 'warning', 'message': '规则记录未找到'}), 200

    success_ipt, ipt_msg, is_bad = perform_iptables_delete_for_rule(rule)
    if success_ipt or is_bad:
        db_del_ok, db_msg = remove_nat_rule_from_db(rule_id)
        msg = 'NAT 规则已删除。'
        if is_bad: msg = '数据库记录已删除 (iptables 中未找到)。'
        if not db_del_ok: msg += f' 但数据库移除失败: {db_msg}'
        return jsonify({'status': 'success' if db_del_ok else 'warning', 'message': msg}), 200
    else:
        return jsonify({'status': 'error', 'message': f'删除 NAT 规则失败: {ipt_msg}'}), 500
