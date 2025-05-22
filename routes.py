from flask import render_template, request, jsonify, redirect, url_for
import time
import shlex
from . import container_manager
from . import nat_manager
from . import commands
from . import database


def index():
    success_list, containers_data = commands.run_incus_command(['list', '--format', 'json'])

    listed_containers = []
    db_containers_dict = {}
    incus_error = False
    incus_error_message = None

    try:
        db_containers_dict = {row['incus_name']: dict(row) for row in database.query_db('SELECT * FROM containers')}
    except sqlite3.OperationalError as e:
        incus_error = True
        incus_error_message = f"数据库错误：容器表未找到，请运行 init_db.py。原始错误: {e}"
        return render_template('index.html',
                               containers=[],
                               images=[],
                               incus_error=(incus_error, incus_error_message),
                               image_error=(True, "无法加载可用镜像列表."))


    incus_container_names_set = set()

    if not success_list:
        incus_error = True
        incus_error_message = containers_data
        for name, data in db_containers_dict.items():
            listed_containers.append({
                'name': name,
                'status': data.get('status', 'Unknown (from DB)'),
                'image_source': data.get('image_source', 'N/A (from DB)'),
                'ip': 'N/A (DB info)',
                'created_at': data.get('created_at', 'N/A (from DB)')
            })

    elif isinstance(containers_data, list):
        for item in containers_data:
            if not isinstance(item, dict) or 'name' not in item:
                continue

            item_name = item['name']
            incus_container_names_set.add(item_name)

            image_source = 'N/A'
            item_config = item.get('config')
            if isinstance(item_config, dict):
                image_source = item_config.get('image.description')
                if not image_source:
                     image_alias = item_config.get('image.alias')
                     if image_alias:
                         image_source = f"Alias: {image_alias}"
                     else:
                         image_fingerprint = item_config.get('image.fingerprint')
                         if isinstance(image_fingerprint, str):
                              image_source = f"Fingerprint: {image_fingerprint[:12]}"
                if not image_source:
                     image_source = 'N/A'

            created_at_str = item.get('created_at')

            ip_address = 'N/A'
            container_state = item.get('state')
            if isinstance(container_state, dict):
                 network_info = container_state.get('network')
                 if isinstance(network_info, dict):
                     for iface_name, iface_data in network_info.items():
                         if isinstance(iface_data, dict):
                             addresses = iface_data.get('addresses')
                             if isinstance(addresses, list):
                                 found_ip = False
                                 for addr_entry in addresses:
                                     if isinstance(addr_entry, dict):
                                         addr = addr_entry.get('address')
                                         family = addr_entry.get('family')
                                         scope = addr_entry.get('scope')
                                         if addr and family == 'inet' and scope == 'global':
                                             ip_address = addr.split('/')[0]
                                             found_ip = True
                                             break
                                 if found_ip: break


            container_info = {
                'name': item_name,
                'status': item.get('status', 'Unknown'),
                'image_source': image_source,
                'ip': ip_address,
                'created_at': created_at_str,
            }
            listed_containers.append(container_info)
            container_manager.sync_container_to_db(item_name, image_source, item.get('status', 'Unknown'), created_at_str)

        current_db_names = {row['incus_name'] for row in database.query_db('SELECT incus_name FROM containers')}
        vanished_names_from_db = [db_name for db_name in current_db_names if db_name not in incus_container_names_set]
        for db_name in vanished_names_from_db:
             container_manager.remove_container_from_db(db_name)
             nat_manager.cleanup_orphaned_nat_rules_in_db(incus_container_names_set)


    else:
        incus_error = True
        incus_error_message = f"Incus list returned unknown data format or structure: {containers_data}"
        for name, data in db_containers_dict.items():
            listed_containers.append({
                'name': name,
                'status': data.get('status', 'Unknown (from DB)'),
                'image_source': data.get('image_source', 'N/A (from DB)'),
                'ip': 'N/A (DB info)',
                'created_at': data.get('created_at', 'N/A (from DB)')
            })

    success_img, images_data = commands.run_incus_command(['image', 'list', '--format', 'json'])
    available_images = []
    image_error = False
    image_error_message = None
    if success_img and isinstance(images_data, list):
        for img in images_data:
            if not isinstance(img, dict): continue

            alias_name = None
            aliases = img.get('aliases')
            if isinstance(aliases, list) and aliases:
                alias_entry = next((a for a in aliases if isinstance(a, dict) and a.get('name')), None)
                if alias_entry:
                     alias_name = alias_entry.get('name')

            if not alias_name:
                fingerprint = img.get('fingerprint')
                alias_name = fingerprint[:12] if isinstance(fingerprint, str) else 'unknown_image'

            description_props = img.get('properties')
            description = 'N/A'
            if isinstance(description_props, dict):
                description = description_props.get('description', 'N/A')

            available_images.append({'name': alias_name, 'description': f"{alias_name} ({description})"})
    else:
        image_error = True
        image_error_message = images_data if not success_img else 'Invalid image data format from Incus.'


    return render_template('index.html',
                           containers=listed_containers,
                           images=available_images,
                           incus_error=(incus_error, incus_error_message),
                           image_error=(image_error, image_error_message))


def create_container():
    name = request.form.get('name')
    image = request.form.get('image')
    if not name or not image:
        return jsonify({'status': 'error', 'message': '容器名称和镜像不能为空'}), 400

    db_exists = database.query_db('SELECT 1 FROM containers WHERE incus_name = ?', [name], one=True)
    if db_exists:
        return jsonify({'status': 'error', 'message': f'名称为 "{name}" 的容器在数据库中已存在记录。请尝试刷新列表或使用其他名称。'}), 409


    success, output = commands.run_incus_command(['launch', image, name], parse_json=False, timeout=120)

    if success:
        time.sleep(5)

        _, list_output = commands.run_incus_command(['list', name, '--format', 'json'])

        created_at = None
        image_source_desc = image
        status_val = 'Pending'

        if isinstance(list_output, list) and len(list_output) > 0 and isinstance(list_output[0], dict):
             container_data = list_output[0]
             status_val = container_data.get('status', status_val)
             created_at = container_data.get('created_at')
             list_cfg = container_data.get('config')
             if isinstance(list_cfg, dict):
                  list_img_desc = list_cfg.get('image.description')
                  if list_img_desc: image_source_desc = list_img_desc
        container_manager.sync_container_to_db(name, image_source_desc, status_val, created_at)

        return jsonify({'status': 'success', 'message': f'容器 {name} 创建并启动操作已提交。状态将很快同步。'}), 200
    else:
        return jsonify({'status': 'error', 'message': f'创建容器 {name} 失败: {output}'}), 500


def container_action(name):
    action = request.form.get('action')
    command_map = {
        'start': ['start', name],
        'stop': ['stop', name, '--force'],
        'restart': ['restart', name, '--force'],
    }

    if action == 'delete':
        success_db_rules, rules = nat_manager.get_nat_rules_for_container(name)
        if not success_db_rules:
             return jsonify({'status': 'error', 'message': f'删除容器前从数据库获取NAT规则失败: {rules}'}), 500

        failed_rule_deletions = []
        warning_rule_deletions = []
        if rules:
            for rule in rules:
                if not all(key in rule for key in ['id', 'host_port', 'container_port', 'protocol', 'ip_at_creation']):
                     failed_rule_deletions.append(f"Rule ID {rule.get('id', 'N/A')} (数据库记录不完整)")
                     continue

                success_iptables_delete, iptables_message, is_bad_rule = nat_manager.perform_iptables_delete_for_rule(rule)

                if not success_iptables_delete:
                    if is_bad_rule:
                         warning_rule_deletions.append(iptables_message)
                         db_success, db_msg = nat_manager.remove_nat_rule_from_db(rule['id'])
                    else:
                         failed_rule_deletions.append(iptables_message)

                else:
                    db_success, db_msg = nat_manager.remove_nat_rule_from_db(rule['id'])
                    if not db_success:
                         pass


        if failed_rule_deletions:
            error_message = f"删除容器 {name} 前，未能移除所有关联的 NAT 规则 ({len(failed_rule_deletions)}/{len(rules) if rules else 0} 条 iptables 删除失败)。请手动检查 iptables。<br>失败详情: " + "; ".join(failed_rule_deletions)
            if warning_rule_deletions:
                 error_message += "<br>跳过的规则 (iptables 未找到): " + "; ".join(warning_rule_deletions)
            return jsonify({'status': 'error', 'message': error_message}), 500


        success_incus_delete, incus_output = commands.run_incus_command(['delete', name, '--force'], parse_json=False, timeout=120)

        if success_incus_delete:
            container_manager.remove_container_from_db(name)
            message = f'容器 {name} 及其关联的 {len(rules) if rules else 0} 条 NAT 规则记录已成功删除。'
            if warning_rule_deletions:
                 message += "<br>注意: 部分 iptables 规则在删除时已不存在。"
            return jsonify({'status': 'success', 'message': message}), 200
        else:
            error_message = f'删除容器 {name} 失败: {incus_output}'
            return jsonify({'status': 'error', 'message': error_message}), 500

    if action not in command_map:
        return jsonify({'status': 'error', 'message': '无效的操作'}), 400

    timeout_val = 60
    if action in ['stop', 'restart']: timeout_val = 120

    success, output = commands.run_incus_command(command_map[action], parse_json=False, timeout=timeout_val)

    if success:
        message = f'容器 {name} {action} 操作提交成功。'
        time.sleep(action in ['stop', 'restart', 'start'] and 3 or 1)

        _, list_output = commands.run_incus_command(['list', name, '--format', 'json'], timeout=10)

        new_status_val = 'Unknown'
        db_image_source = 'N/A'
        db_created_at = None

        old_db_entry = database.query_db('SELECT image_source, created_at, status FROM containers WHERE incus_name = ?', [name], one=True)
        if old_db_entry:
             db_image_source = old_db_entry['image_source']
             db_created_at = old_db_entry['created_at']
             new_status_val = old_db_entry['status']

        if isinstance(list_output, list) and len(list_output) > 0 and isinstance(list_output[0], dict):
            container_data = list_output[0]
            new_status_val = container_data.get('status', new_status_val)
            list_cfg = container_data.get('config')
            if isinstance(list_cfg, dict):
                 list_img_desc = list_cfg.get('image.description')
                 if list_img_desc: db_image_source = list_img_desc
            list_created_at = container_data.get('created_at')
            if list_created_at: db_created_at = list_created_at

            message = f'容器 {name} {action} 操作成功，新状态: {new_status_val}。'
        else:
             if action == 'start': new_status_val = 'Running'
             elif action == 'stop': new_status_val = 'Stopped'
             elif action == 'restart': new_status_val = 'Running'
             message = f'容器 {name} {action} 操作提交成功，但无法获取最新状态（list命令失败或容器状态未立即更新）。'

        container_manager.sync_container_to_db(name, db_image_source, new_status_val, db_created_at)

        return jsonify({'status': 'success', 'message': message}), 200
    else:
        return jsonify({'status': 'error', 'message': f'容器 {name} {action} 操作失败: {output}'}), 500


def exec_command(name):
    command_to_exec = request.form.get('command')
    if not command_to_exec:
        return jsonify({'status': 'error', 'message': '执行的命令不能为空'}), 400

    try:
        command_parts = shlex.split(command_to_exec)
    except ValueError as e:
        return jsonify({'status': 'error', 'message': f'无效的命令格式: {e}'}), 400

    if not command_parts:
         return jsonify({'status': 'error', 'message': '执行的命令不能为空'}), 400

    success, output = commands.run_incus_command(['exec', name, '--'] + command_parts, parse_json=False, timeout=120)

    if success:
        return jsonify({'status': 'success', 'output': output}), 200
    else:
        return jsonify({'status': 'error', 'output': output, 'message': '命令执行失败'}), 500


def container_info(name):
    info_output, error_message = container_manager.get_container_raw_info(name)

    if info_output is None:
        return jsonify({'status': 'NotFound', 'message': error_message}), 404
    else:
        return jsonify(info_output), 200


def add_nat_rule(name):
    host_port = request.form.get('host_port')
    container_port = request.form.get('container_port')
    protocol = request.form.get('protocol')

    if not host_port or not container_port or not protocol:
         return jsonify({'status': 'error', 'message': '主机端口、容器端口和协议不能为空'}), 400
    try:
        host_port = int(host_port)
        container_port = int(container_port)
        if not (1 <= host_port <= 65535) or not (1 <= container_port <= 65535):
            raise ValueError("端口号必须在 1 到 65535 之间。")
    except ValueError as e:
         return jsonify({'status': 'error', 'message': f'端口号无效: {e}'}), 400

    if protocol not in ['tcp', 'udp']:
         return jsonify({'status': 'error', 'message': '协议必须是 tcp 或 udp'}), 400

    db_check_success, rule_exists = nat_manager.check_nat_rule_exists_in_db(name, host_port, protocol)
    if not db_check_success:
        return jsonify({'status': 'error', 'message': f"检查现有 NAT 规则记录失败: {rule_exists}"}), 500
    if rule_exists:
        message = f'容器 {name} 的主机端口 {host_port}/{protocol} NAT 规则已存在记录，跳过添加。'
        return jsonify({'status': 'warning', 'message': message}), 200

    container_info_data, info_error_message = container_manager.get_container_raw_info(name)

    if container_info_data is None:
         return jsonify({'status': 'error', 'message': f'无法获取容器 {name} 信息: {info_error_message}'}), 404


    if container_info_data.get('status') != 'Running':
         status_msg = container_info_data.get('status', 'Unknown')
         return jsonify({'status': 'error', 'message': f'容器 {name} 必须处于 Running 状态才能添加 NAT 规则 (当前状态: {status_msg})。'}), 400

    container_ip = container_info_data.get('ip')

    if not container_ip or container_ip == 'N/A':
         return jsonify({'status': 'error', 'message': f'无法获取容器 {name} 的 IP 地址。请确保容器正在运行且已分配 IP。'}), 500


    rule_details_for_iptables = {
         'host_port': host_port,
         'container_port': container_port,
         'protocol': protocol,
         'ip_at_creation': container_ip # Use the IP found *at the time of adding*
    }
    success_iptables, output, is_bad_rule = nat_manager.perform_iptables_delete_for_rule(rule_details_for_iptables) # Check if rule *already* exists implicitly by attempting delete


    if success_iptables:
        nat_manager.remove_nat_rule_from_db(rule_details_for_iptables.get('id', -1)) # Remove from DB if it existed and was deleted

    iptables_command = [
        '-t', 'nat',
        '-A', 'PREROUTING',
        '-p', protocol,
        '--dport', str(host_port),
        '-j', 'DNAT',
        '--to-destination', f'{container_ip}:{container_port}'
    ]


    success_iptables_add, output_add = commands.run_iptables_command(iptables_command, parse_json=False)

    if success_iptables_add:
        rule_details = {
             'container_name': name,
             'host_port': host_port,
             'container_port': container_port,
             'protocol': protocol,
             'ip_at_creation': container_ip
        }
        db_success, db_result = nat_manager.add_nat_rule_to_db(rule_details)

        message = f'已成功为容器 {name} 添加 NAT 规则: 主机端口 {host_port}/{protocol} 转发到容器 IP {container_ip} 端口 {container_port}。'

        if not db_success:
             message += f" 但记录规则到数据库失败: {db_result}"
             return jsonify({'status': 'warning', 'message': message}), 200

        return jsonify({'status': 'success', 'message': message, 'rule_id': db_result}), 200

    else:
        message = f'添加 NAT 规则失败: {output_add}'
        return jsonify({'status': 'error', 'message': message}), 500

def list_nat_rules(name):
    success, rules = nat_manager.get_nat_rules_for_container(name)
    if success:
        return jsonify({'status': 'success', 'rules': rules}), 200
    else:
        return jsonify({'status': 'error', 'message': rules}), 500

def delete_nat_rule(rule_id):
    success_db, rule = nat_manager.get_nat_rule_by_id(rule_id)

    if not success_db:
         return jsonify({'status': 'error', 'message': f'删除NAT规则前从数据库获取规则失败: {rule}'}), 500

    if not rule:
        return jsonify({'status': 'warning', 'message': f'数据库中找不到ID为 {rule_id} 的NAT规则记录，可能已被手动删除。跳过 iptables 删除。'}), 200

    container_name = rule.get('container_name', 'unknown')
    host_port = rule['host_port']
    container_port = rule['container_port']
    protocol = rule['protocol']
    ip_at_creation = rule['ip_at_creation']

    rule_details_for_iptables = {
         'id': rule_id,
         'host_port': host_port,
         'container_port': container_port,
         'protocol': protocol,
         'ip_at_creation': ip_at_creation
    }

    success_iptables, iptables_message, is_bad_rule = nat_manager.perform_iptables_delete_for_rule(rule_details_for_iptables)

    if success_iptables or is_bad_rule:
        db_success, db_message = nat_manager.remove_nat_rule_from_db(rule_id)

        message = f'已成功删除ID为 {rule_id} 的NAT规则记录。'
        if is_bad_rule:
             message = f'数据库记录已删除 (ID {rule_id})。注意：该规则在 iptables 中未找到或已不存在。'

        if not db_success:
             message += f" 但从数据库移除记录失败: {db_message}"
             return jsonify({'status': 'warning', 'message': message}), 200

        return jsonify({'status': 'success', 'message': message}), 200
    else:
        message = f'删除ID为 {rule_id} 的NAT规则失败: {iptables_message}'
        return jsonify({'status': 'error', 'message': message}), 500
