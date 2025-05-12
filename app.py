# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for
import subprocess
import json
import sqlite3
import datetime
import os
import time
import re
import shlex
import sys

app = Flask(__name__)
DATABASE_NAME = 'incus_manager.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def query_db(query, args=(), one=False):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(query, args)
        if not query.strip().upper().startswith('SELECT'):
             conn.commit()
        rv = cur.fetchall()
    except sqlite3.Error as e:
        app.logger.error(f"数据库查询错误: {e}\nQuery: {query}\nArgs: {args}")
        rv = []
        if conn:
             conn.rollback()
    finally:
        if conn:
            conn.close()
    return (rv[0] if rv else None) if one else rv

def run_command(command_parts, parse_json=True, timeout=60):
    try:
        env_vars = os.environ.copy()
        env_vars['LC_ALL'] = 'C.UTF-8'
        env_vars['LANG'] = 'C.UTF-8'

        app.logger.info(f"Executing command: {' '.join(shlex.quote(part) for part in command_parts)}")
        result = subprocess.run(command_parts, capture_output=True, text=True, check=False, timeout=timeout, env=env_vars)

        if result.returncode != 0:
            error_message = result.stderr.strip() if result.stderr else result.stdout.strip()
            app.logger.error(f"Command failed (Exit code {result.returncode}): {' '.join(shlex.quote(part) for part in command_parts)}\nError: {error_message}")
            full_output = f"STDOUT:\n{result.stdout.strip()}\nSTDERR:\n{result.stderr.strip()}"
            return False, f"命令执行失败 (退出码 {result.returncode}): {error_message}\n完整输出:\n{full_output}"

        if parse_json:
            try:
                output_text = result.stdout.strip()
                if output_text.startswith(u'\ufeff'):
                    output_text = output_text[1:]
                return True, json.loads(output_text)
            except json.JSONDecodeError as e:
                app.logger.error(f"Failed to parse JSON from command output: {result.stdout}\nError: {e}")
                return False, f"解析命令输出为 JSON 失败: {e}\n原始输出: {result.stdout.strip()}"
        else:
            return True, result.stdout.strip()

    except FileNotFoundError:
        command_name = command_parts[0] if command_parts else 'command'
        app.logger.error(f"Command not found: {command_name}. Is it installed and in PATH?")
        return False, f"命令 '{command_name}' 未找到。请确保它已安装并在系统 PATH 中。"
    except subprocess.TimeoutExpired:
        app.logger.error(f"Command timed out (>{timeout}s): {' '.join(shlex.quote(part) for part in command_parts)}")
        return False, f"命令执行超时 (>{timeout}秒)。"
    except Exception as e:
        app.logger.error(f"执行命令时发生异常: {e}")
        return False, f"执行命令时发生异常: {str(e)}"

def run_incus_command(command_args, parse_json=True, timeout=60):
    return run_command(['incus'] + command_args, parse_json, timeout)


def sync_container_to_db(name, image_source, status, created_at_str):
    try:
        created_at_to_db = str(created_at_str) if created_at_str is not None else None

        if created_at_to_db:
            original_created_at_to_db = created_at_to_db
            try:
                if created_at_to_db.endswith('Z'):
                   created_at_to_db = created_at_to_db[:-1] + '+00:00'

                tz_match_hhmm = re.search(r'([+-])(\d{4})$', created_at_to_db)
                if tz_match_hhmm:
                    sign = tz_match_hhmm.group(1)
                    hhmm = tz_match_hhmm.group(2)
                    created_at_to_db = created_at_to_db[:-4] + f"{sign}{hhmm[:2]}:{hhmm[2:]}"

                parts = created_at_to_db.split('.')
                if len(parts) > 1:
                    time_tz_part = parts[1]
                    tz_start_match = re.search(r'[+-]\d', time_tz_part)
                    if tz_start_match:
                         micro_part = time_tz_part[:tz_start_match.start()]
                         tz_part = time_tz_part[tz_start_match.start():]
                         if len(micro_part) > 6:
                            micro_part = micro_part[:6]
                         time_tz_part = micro_part + tz_part
                    else:
                        if len(time_tz_part) > 6:
                            time_tz_part = time_tz_part[:6]

                    created_at_to_db = parts[0] + '.' + time_tz_part
                elif re.search(r'[+-]\d{2}:?\d{2}$', created_at_to_db):
                     time_segment = created_at_to_db.split('T')[-1]
                     if '.' not in time_segment.split(re.search(r'[+-]', time_segment).group(0))[0]:
                           tz_part = re.search(r'[+-]\d{2}:?\d{2}$', created_at_to_db).group(0)
                           if not '.' in created_at_to_db:
                              created_at_to_db = created_at_to_db.replace(tz_part, '.000000' + tz_part)


                datetime.datetime.fromisoformat(created_at_to_db)

            except (ValueError, AttributeError, TypeError) as ve:
                app.logger.warning(f"无法精确解析 Incus 创建时间 '{original_created_at_to_db}' for {name} 为 ISO 格式 ({ve}). 将尝试使用数据库记录的原值或当前时间.")
                old_db_entry = query_db('SELECT created_at FROM containers WHERE incus_name = ?', [name], one=True)
                if old_db_entry and old_db_entry['created_at']:
                     try:
                          datetime.datetime.fromisoformat(old_db_entry['created_at'])
                          created_at_to_db = old_db_entry['created_at']
                     except (ValueError, TypeError):
                          app.logger.warning(f"数据库记录的创建时间 '{old_db_entry['created_at']}' for {name} 也是无效 ISO 格式.")
                          created_at_to_db = datetime.datetime.now().isoformat()
                else:
                     created_at_to_db = datetime.datetime.now().isoformat()

        else:
             old_db_entry = query_db('SELECT created_at FROM containers WHERE incus_name = ?', [name], one=True)
             if old_db_entry and old_db_entry['created_at']:
                 try:
                      datetime.datetime.fromisoformat(old_db_entry['created_at'])
                      created_at_to_db = old_db_entry['created_at']
                 except (ValueError, TypeError):
                      app.logger.warning(f"数据库记录的创建时间 '{old_db_entry['created_at']}' for {name} 也是无效 ISO 格式.")
                      created_at_to_db = datetime.datetime.now().isoformat()
             else:
                  created_at_to_db = datetime.datetime.now().isoformat()


        query_db('''
            INSERT INTO containers (incus_name, image_source, status, created_at, last_synced)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(incus_name) DO UPDATE SET
                image_source = excluded.image_source,
                status = excluded.status,
                created_at = excluded.created_at,
                last_synced = CURRENT_TIMESTAMP
        ''', (name, image_source, status, created_at_to_db))
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 sync_container_to_db for {name}: {e}")


def remove_container_from_db(name):
    try:
        query_db('DELETE FROM containers WHERE incus_name = ?', [name])
        query_db('DELETE FROM nat_rules WHERE container_name = ?', [name]) # Also remove associated NAT rules
        app.logger.info(f"从数据库中移除了容器及其NAT规则: {name}")
    except sqlite3.Error as e:
         app.logger.error(f"数据库错误 remove_container_from_db for {name}: {e}")


def get_container_ip(container_name):
    success, data = run_incus_command(['list', container_name, '--format', 'json'])

    if not success:
        app.logger.warning(f"无法获取容器 {container_name} 的列表信息以解析IP: {data}")
        return None

    if not isinstance(data, list) or not data:
        app.logger.warning(f"incus list for {container_name} returned unexpected data format or empty: {data}")
        return None

    container_data = data[0]

    if not isinstance(container_data, dict) or 'state' not in container_data or not isinstance(container_data['state'], dict):
         app.logger.warning(f"incus list data for {container_name} missing 'state' or 'state' not a dict: {container_data}")
         return None

    container_state = container_data['state']
    network_info = container_state.get('network')

    if not isinstance(network_info, dict):
        app.logger.warning(f"Container {container_name} 'state' does not contain network info or it's not a dict.")
        return None

    for iface_name, iface_data in network_info.items():
        if (iface_name.startswith('eth') or iface_name.startswith('enp') or iface_name.startswith('ens')) and isinstance(iface_data, dict):
            addresses = iface_data.get('addresses')
            if isinstance(addresses, list):
                for addr_entry in addresses:
                    if isinstance(addr_entry, dict):
                        addr = addr_entry.get('address')
                        family = addr_entry.get('family')
                        scope = addr_entry.get('scope')
                        if addr and family == 'inet' and scope == 'global':
                            ip_address = addr.split('/')[0]
                            app.logger.info(f"成功从 incus list JSON 解析出容器 {container_name} 的全局 IPv4 地址: {ip_address}")
                            return ip_address

    app.logger.warning(f"在容器 {container_name} 的 incus list JSON 输出中无法找到全局 IPv4 地址 (用于NAT等功能)。请确保容器正在运行且已分配IP。")
    return None

# --- NAT Rule Database Functions ---

def add_nat_rule_to_db(container_name, host_port, container_port, protocol, container_ip):
    """Adds a NAT rule record to the database."""
    try:
        query_db('''
            INSERT INTO nat_rules (container_name, host_port, container_port, protocol, ip_at_creation)
            VALUES (?, ?, ?, ?, ?)
        ''', (container_name, host_port, container_port, protocol, container_ip))
        app.logger.info(f"Added NAT rule to DB: {container_name}, host={host_port}/{protocol}, container={container_ip}:{container_port}")
        return True, "规则记录成功添加到数据库。"
    except sqlite3.IntegrityError:
         return False, f"数据库已存在容器 {container_name} 的主机端口 {host_port}/{protocol} 规则记录。"
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 add_nat_rule_to_db for {container_name}: {e}")
        return False, f"添加规则记录到数据库失败: {e}"

def get_nat_rules_for_container(container_name):
    """Retrieves all NAT rules for a given container from the database."""
    try:
        rules = query_db('SELECT id, host_port, container_port, protocol, ip_at_creation, created_at FROM nat_rules WHERE container_name = ?', [container_name])
        # Convert Row objects to dicts for easier JSON serialization
        return True, [dict(row) for row in rules]
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 get_nat_rules_for_container for {container_name}: {e}")
        return False, f"从数据库获取规则失败: {e}"

def get_nat_rule_by_id(rule_id):
    """Retrieves a single NAT rule by its ID from the database."""
    try:
        rule = query_db('SELECT id, container_name, host_port, container_port, protocol, ip_at_creation FROM nat_rules WHERE id = ?', [rule_id], one=True)
        return True, dict(rule) if rule else None
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 get_nat_rule_by_id for id {rule_id}: {e}")
        return False, f"从数据库获取规则 (ID {rule_id}) 失败: {e}"


def remove_nat_rule_from_db(rule_id):
    """Removes a NAT rule record from the database by its ID."""
    try:
        query_db('DELETE FROM nat_rules WHERE id = ?', [rule_id])
        app.logger.info(f"Removed NAT rule from DB: ID {rule_id}")
        return True, "规则记录成功从数据库移除。"
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 remove_nat_rule_from_db for id {rule_id}: {e}")
        return False, f"从数据库移除规则记录失败: {e}"


# --- Routes ---

@app.route('/')
def index():
    success, containers_data = run_incus_command(['list', '--format', 'json'])

    listed_containers = []
    db_containers_dict = {}
    incus_error = False
    incus_error_message = None

    try:
        db_containers_dict = {row['incus_name']: dict(row) for row in query_db('SELECT * FROM containers')}
    except sqlite3.OperationalError as e:
        app.logger.error(f"数据库表 'containers' 可能不存在: {e}. 请运行 init_db.py.")
        incus_error = True
        incus_error_message = f"数据库错误：容器表未找到，请运行 init_db.py。原始错误: {e}"
        return render_template('index.html',
                               containers=[],
                               images=[],
                               incus_error=(incus_error, incus_error_message),
                               image_error=(True, "无法加载可用镜像列表."))


    if not success:
        incus_error = True
        incus_error_message = containers_data
        app.logger.warning(f"无法从 Incus 获取容器列表 ({incus_error_message})，尝试从数据库加载。")
        for name, data in db_containers_dict.items():
            listed_containers.append({
                'name': name,
                'status': data.get('status', 'Unknown (from DB)'),
                'image_source': data.get('image_source', 'N/A (from DB)'),
                'ip': 'N/A (DB info)', # Cannot reliably get live IP without Incus list
                'created_at': data.get('created_at', 'N/A (from DB)')
            })

    elif isinstance(containers_data, list):
        incus_container_names = set()
        for item in containers_data:
            if not isinstance(item, dict) or 'name' not in item:
                app.logger.warning(f"Skipping invalid item in containers_data: {item}")
                continue

            item_name = item['name']
            incus_container_names.add(item_name)

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
                         if image_fingerprint and isinstance(image_fingerprint, str):
                              image_source = f"Fingerprint: {image_fingerprint[:12]}"
                if not image_source:
                     image_source = 'N/A'


            created_at_str = item.get('created_at')

            ip_address = 'N/A' # Default
            container_state = item.get('state')
            if isinstance(container_state, dict):
                 network_info = container_state.get('network')
                 if isinstance(network_info, dict):
                     for iface_name, iface_data in network_info.items():
                         if (iface_name.startswith('eth') or iface_name.startswith('enp') or iface_name.startswith('ens')) and isinstance(iface_data, dict):
                             addresses = iface_data.get('addresses')
                             if isinstance(addresses, list):
                                 found_ip = False
                                 for addr_entry in addresses:
                                     if isinstance(addr_entry, dict):
                                         addr = addr_entry.get('address')
                                         family = addr_entry.get('family')
                                         scope = addr_entry.get('scope')
                                         # Use the same logic as get_container_ip for consistency in index view
                                         if addr and family == 'inet' and scope == 'global':
                                             ip_address = addr
                                             found_ip = True
                                             break # Found a global IPv4, move to next container
                                 if found_ip: break # Found a global IPv4 on this interface, move to next interface/container


            container_info = {
                'name': item_name,
                'status': item.get('status', 'Unknown'),
                'image_source': image_source,
                'ip': ip_address, # Display live IP if available
                'created_at': created_at_str,
            }
            listed_containers.append(container_info)
            sync_container_to_db(item_name, image_source, item.get('status', 'Unknown'), created_at_str)


        current_db_names = {row['incus_name'] for row in query_db('SELECT incus_name FROM containers')}
        for db_name in current_db_names:
            if db_name not in incus_container_names:
                remove_container_from_db(db_name)

    else:
        incus_error = True
        incus_error_message = containers_data if not success else f"Incus list 返回了未知数据格式或错误结构: {containers_data}"
        app.logger.error(incus_error_message)
        app.logger.warning("尝试从数据库加载容器列表。")

        # If Incus list failed, load from DB but IP will be missing/old
        for name, data in db_containers_dict.items():
            listed_containers.append({
                'name': name,
                'status': data.get('status', 'Unknown (from DB)'),
                'image_source': data.get('image_source', 'N/A (from DB)'),
                'ip': 'N/A (DB info)', # Cannot reliably get live IP without Incus list
                'created_at': data.get('created_at', 'N/A (from DB)')
            })


    success_img, images_data = run_incus_command(['image', 'list', '--format', 'json'])
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
        app.logger.error(f"获取镜像列表失败: {image_error_message}")


    return render_template('index.html',
                           containers=listed_containers,
                           images=available_images,
                           incus_error=(incus_error, incus_error_message),
                           image_error=(image_error, image_error_message))


@app.route('/container/create', methods=['POST'])
def create_container():
    name = request.form.get('name')
    image = request.form.get('image')
    if not name or not image:
        return jsonify({'status': 'error', 'message': '容器名称和镜像不能为空'}), 400

    success, output = run_incus_command(['launch', image, name], parse_json=False, timeout=120)

    if success:
        time.sleep(5) # Give container a moment to start and get IP

        _, list_output = run_incus_command(['list', name, '--format', 'json'])

        created_at = None
        image_source_desc = image
        status_val = 'Pending'

        if isinstance(list_output, list) and len(list_output) > 0 and isinstance(list_output[0], dict):
             container_data = list_output[0]
             status_val = container_data.get('status', 'Unknown')
             created_at = container_data.get('created_at')
             list_cfg = container_data.get('config')
             if isinstance(list_cfg, dict):
                  list_img_desc = list_cfg.get('image.description')
                  if list_img_desc: image_source_desc = list_img_desc
             app.logger.info(f"Successfully got list info for new container {name}.")
        else:
             app.logger.warning(f"Failed to get list info for new container {name}. list output: {list_output}")

        sync_container_to_db(name, image_source_desc, status_val, created_at)

        return jsonify({'status': 'success', 'message': f'容器 {name} 创建并启动成功。后台正在同步状态。'})
    else:
        return jsonify({'status': 'error', 'message': f'创建容器 {name} 失败: {output}'}), 500


@app.route('/container/<name>/action', methods=['POST'])
def container_action(name):
    action = request.form.get('action')
    commands = {
        'start': ['incus', 'start', name],
        'stop': ['incus', 'stop', name, '--force'], # Use force for quicker state change
        'restart': ['incus', 'restart', name, '--force'], # Use force
        'delete': ['incus', 'delete', name, '--force'], # Use force
    }
    if action not in commands:
        return jsonify({'status': 'error', 'message': '无效的操作'}), 400

    timeout_val = 60
    if action in ['stop', 'restart', 'delete']: timeout_val = 120 # Give more time for state changes/deletion

    success, output = run_command(commands[action], parse_json=False, timeout=timeout_val)

    if success:
        message = f'容器 {name} {action} 操作提交成功。'
        # Give Incus a moment to update status
        time.sleep(action in ['stop', 'restart', 'start'] and 3 or action == 'delete' and 1 or 1)

        if action == 'delete':
            remove_container_from_db(name)
            message = f'容器 {name} 已删除。'
        else:
            # Attempt to get latest status after action
            _, list_output = run_incus_command(['list', name, '--format', 'json'], timeout=10)

            new_status_val = 'Unknown'
            db_image_source = 'N/A'
            db_created_at = None

            # Fetch existing DB info to retain image_source and created_at if list fails
            old_db_entry = query_db('SELECT image_source, created_at, status FROM containers WHERE incus_name = ?', [name], one=True)
            if old_db_entry:
                 db_image_source = old_db_entry['image_source']
                 db_created_at = old_db_entry['created_at']
                 new_status_val = old_db_entry['status'] # Start with old status

            if isinstance(list_output, list) and len(list_output) > 0 and isinstance(list_output[0], dict):
                container_data = list_output[0]
                new_status_val = container_data.get('status', new_status_val) # Use new status if available
                list_cfg = container_data.get('config')
                if isinstance(list_cfg, dict):
                     list_img_desc = list_cfg.get('image.description')
                     if list_img_desc: db_image_source = list_img_desc # Update image source if available
                list_created_at = container_data.get('created_at')
                if list_created_at: db_created_at = list_created_at # Update created_at if available

                message = f'容器 {name} {action} 操作成功，新状态: {new_status_val}。'
            else:
                 # If list failed, set a best-guess status based on the action
                 if action == 'start': new_status_val = 'Running'
                 elif action == 'stop': new_status_val = 'Stopped'
                 elif action == 'restart': new_status_val = 'Running'
                 # For 'delete', the remove_container_from_db call handles it
                 message = f'容器 {name} {action} 操作提交成功，但无法获取最新状态（list命令失败或容器状态未立即更新）。'
                 app.logger.warning(f"Failed to get updated status for {name} after {action}. list output: {list_output}")

            # Sync updated status (and potentially other info) to DB
            sync_container_to_db(name, db_image_source, new_status_val, db_created_at)


        return jsonify({'status': 'success', 'message': message})
    else:
        return jsonify({'status': 'error', 'message': f'容器 {name} {action} 操作失败: {output}'}), 500


@app.route('/container/<name>/exec', methods=['POST'])
def exec_command(name):
    command_to_exec = request.form.get('command')
    if not command_to_exec:
        return jsonify({'status': 'error', 'message': '执行的命令不能为空'}), 400

    try:
        # Use shlex.split for safer command handling
        command_parts = shlex.split(command_to_exec)
    except ValueError as e:
        return jsonify({'status': 'error', 'message': f'无效的命令格式: {e}'}), 400

    if not command_parts:
         return jsonify({'status': 'error', 'message': '执行的命令不能为空'}), 400

    # Add a timeout for command execution within the container
    success, output = run_incus_command(['exec', name, '--'] + command_parts, parse_json=False, timeout=120) # Increased timeout for exec

    if success:
        return jsonify({'status': 'success', 'output': output})
    else:
        # Include stderr in the error output
        return jsonify({'status': 'error', 'output': output, 'message': '命令执行失败'}), 500


@app.route('/container/<name>/info')
def container_info(name):
    # This route primarily provides the structured data for display
    # The actual Incus info text is still useful for full details in the modal
    db_info = query_db('SELECT * FROM containers WHERE incus_name = ?', [name], one=True)

    # Attempt to get live data from Incus first
    success_live, live_data = run_incus_command(['list', name, '--format', 'json'])

    if success_live and isinstance(live_data, list) and len(live_data) > 0 and isinstance(live_data[0], dict):
        # Use live data if successful
        container_data = live_data[0]
        info_output = {
            'name': container_data.get('name', name),
            'status': container_data.get('status', 'Unknown'),
            'status_code': container_data.get('status_code', 0),
            'type': container_data.get('type', 'unknown'),
            'architecture': container_data.get('architecture', 'N/A'),
            'ephemeral': container_data.get('ephemeral', False),
            'created_at': container_data.get('created_at', None),
            'profiles': container_data.get('profiles', []),
            'config': container_data.get('config', {}),
            'devices': container_data.get('devices', {}),
            'snapshots': container_data.get('snapshots', []),
             'state': container_data.get('state', {}), # Include full state
            'description': container_data.get('config', {}).get('image.description', 'N/A'), # Common place for description
            'ip': 'N/A', # Will be filled below from state if available
            'live_data_available': True,
            'message': '数据主要来自 Incus 实时信息 (通过 JSON)。',
        }

         # Try to parse IP from live state data
        container_state = info_output.get('state')
        if isinstance(container_state, dict):
            network_info = container_state.get('network')
            if isinstance(network_info, dict):
                for iface_name, iface_data in network_info.items():
                    if isinstance(iface_data, dict): # Check common interfaces
                        addresses = iface_data.get('addresses')
                        if isinstance(addresses, list):
                            for addr_entry in addresses:
                                if isinstance(addr_entry, dict):
                                    addr = addr_entry.get('address')
                                    family = addr_entry.get('family')
                                    scope = addr_entry.get('scope')
                                    if addr and family == 'inet' and scope == 'global':
                                        info_output['ip'] = addr.split('/')[0] # Global IPv4 without mask
                                        break
                            if info_output['ip'] != 'N/A': break # Found IP, stop looking


    elif db_info:
        # Use database data if live data failed but DB record exists
        info_output = {
            'name': db_info['incus_name'],
            'status': db_info.get('status', 'Unknown'),
            'status_code': 0, # Cannot get live status code from DB
            'type': 'container', # Default type
            'architecture': db_info.get('architecture', 'N/A'), # Assuming architecture might be stored or N/A
            'ephemeral': False, # Cannot tell from DB
            'created_at': db_info.get('created_at', None),
            'profiles': [], # Not stored in DB
            'config': {}, # Not stored in DB
            'devices': {}, # Not stored in DB
            'snapshots': [], # Not stored in DB
             'state': {'status': db_info.get('status', 'Unknown'), 'status_code': 0, 'network': {}}, # Basic state from DB status
            'description': db_info.get('image_source', 'N/A'), # Use image source from DB as description fallback
            'ip': 'N/A', # Cannot reliably get live IP from DB
            'live_data_available': False,
            'message': '无法从 Incus 获取实时信息，数据主要来自数据库快照。',
        }
         # Attempt to parse IP from DB if it happens to be stored there (unlikely unless explicitly added)
         # Or if you had a separate field for last known IP. Sticking to N/A for simplicity.


    else:
        # Neither live data nor DB record found
        info_output = {
            'name': name,
            'status': 'NotFound',
            'status_code': -1,
            'message': f"获取容器 {name} 信息失败: 数据库中无记录且无法从 Incus 获取实时信息。",
            'live_data_available': False,
            'ip': 'N/A',
        }
        return jsonify(info_output), 404 # Return 404 if container not found anywhere


    # Optionally, fetch and include Incus info text output for raw details
    # success_text, text_data = run_incus_command(['info', name], parse_json=False)
    # if success_text:
    #      info_output['incus_info_text'] = text_data
    # else:
    #      info_output['incus_info_text'] = f"无法获取 incus info 文本输出: {text_data if not success_text else '未知错误'}"


    return jsonify(info_output)


@app.route('/container/<name>/add_nat_rule', methods=['POST'])
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

    # Check if the container is running
    _, list_output = run_incus_command(['list', name, '--format', 'json'], timeout=5)
    container_status = 'Unknown'
    if isinstance(list_output, list) and len(list_output) > 0 and isinstance(list_output[0], dict):
         container_status = list_output[0].get('status', 'Unknown')
    else:
         # Fallback to DB status if list fails, but warn it might be stale
         db_info = query_db('SELECT status FROM containers WHERE incus_name = ?', [name], one=True)
         if db_info:
             container_status = db_info['status']
             app.logger.warning(f"Could not get live status for {name}, falling back to DB status: {container_status}")
         else:
            return jsonify({'status': 'error', 'message': f'容器 {name} 不存在或无法获取其状态。'}), 404

    if container_status != 'Running':
         return jsonify({'status': 'error', 'message': f'容器 {name} 必须处于 Running 状态才能添加 NAT 规则 (当前状态: {container_status})。'}), 400

    # Get the container's current IP using the reliable method
    container_ip = get_container_ip(name)

    if not container_ip:
         return jsonify({'status': 'error', 'message': f'无法获取容器 {name} 的 IP 地址。请确保容器正在运行且已分配 IP。'}), 500

    # Construct the iptables command to add the rule
    iptables_command = [
        'iptables',
        '-t', 'nat',
        '-A', 'PREROUTING',
        '-p', protocol,
        '--dport', str(host_port),
        '-j', 'DNAT',
        '--to-destination', f'{container_ip}:{container_port}'
    ]

    app.logger.info(f"Adding NAT rule via iptables: {' '.join(shlex.quote(part) for part in iptables_command)}")

    # Execute the iptables command
    success, output = run_command(iptables_command, parse_json=False)

    if success:
        # Add the rule to the database record only if iptables command succeeded
        db_success, db_message = add_nat_rule_to_db(name, host_port, container_port, protocol, container_ip)
        message = f'已成功为容器 {name} 添加 NAT 规则: 主机端口 {host_port}/{protocol} 转发到容器 IP {container_ip} 端口 {container_port}。'
        if not db_success:
             message += f" 但记录规则到数据库失败: {db_message}"
             app.logger.error(f"Failed to record NAT rule for {name} in DB after successful iptables: {db_message}")
             # Decide if you want to fail the request or just warn. Warning seems better.
             # return jsonify({'status': 'warning', 'message': message, 'output': output}), 500 # Or 200?
             return jsonify({'status': 'success', 'message': message, 'output': output}) # Treat iptables success as overall success


        return jsonify({'status': 'success', 'message': message, 'output': output})
    else:
        # If iptables command failed, report the error and DO NOT add to DB
        message = f'添加 NAT 规则失败: {output}'
        app.logger.error(f"iptables command failed for {name}: {output}")
        return jsonify({'status': 'error', 'message': message, 'output': output}), 500

@app.route('/container/<name>/nat_rules', methods=['GET'])
def list_nat_rules(name):
    """API endpoint to get NAT rules for a specific container from the database."""
    success, rules = get_nat_rules_for_container(name)
    if success:
        # Format the rules for display if needed, or return raw data
        # For now, returning raw data, formatting will be done in frontend
        return jsonify({'status': 'success', 'rules': rules})
    else:
        return jsonify({'status': 'error', 'message': rules}), 500

@app.route('/container/nat_rule/<int:rule_id>', methods=['DELETE'])
def delete_nat_rule(rule_id):
    """API endpoint to delete a NAT rule by its ID."""
    # Get rule details from DB to construct the iptables command
    success_db, rule = get_nat_rule_by_id(rule_id)

    if not success_db:
         return jsonify({'status': 'error', 'message': rule}), 500

    if not rule:
        return jsonify({'status': 'error', 'message': f'数据库中找不到ID为 {rule_id} 的NAT规则记录。'}), 404

    container_name = rule.get('container_name', 'unknown')
    host_port = rule['host_port']
    container_port = rule['container_port']
    protocol = rule['protocol']
    ip_at_creation = rule['ip_at_creation'] # Use the IP recorded at creation time

    # Construct the iptables command to delete the rule
    # Use the exact parameters used for insertion to match the rule precisely
    # Note: If the rule was added with a specific interface (-i) or source IP (-s),
    # the deletion command must also include those for an exact match.
    # Our current ADD command only uses -p, --dport, -j DNAT, --to-destination.
    # We must include the destination IP (container_ip) in the delete command
    # because DNAT rules match on the destination IP/port/protocol in the PREROUTING chain.
    # The IP at creation is needed because the container's IP might change.

    # To delete, we need the *source* IP match of the *packet entering* the chain (any),
    # and the *destination* IP match of the *packet entering* the chain (the host's IP Incus is mapping *to*),
    # the protocol, and the destination port (host_port).
    # However, the DNAT rule itself *changes* the destination IP/port.
    # When listing rules (`iptables -t nat -L PREROUTING -n -v`), a rule added like:
    # `iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80`
    # will often be listed showing the *original* match criteria (`-p tcp dpt:8080`)
    # and the *target* (`to:172.17.0.2:80`).
    # The `-D` command needs to match the criteria used in `-A`.
    # Let's assume the rule definition using `-p`, `--dport`, `-j DNAT`, `--to-destination` is sufficient for `-D`.
    # The container's IP (ip_at_creation) is part of the `--to-destination` *target*, not the match criteria in PREROUTING.
    # The match criteria in PREROUTING are typically:
    # -p protocol --dport host_port
    # The target is -j DNAT --to-destination container_ip:container_port.
    # So, the -D command should specify the match criteria that identifies the rule.
    # A safer way might be to list rules by line number and delete by number, but line numbers change.
    # Deleting by specification is standard but requires matching the -A args.
    # Let's try deleting based on -p, --dport, and the target IP/port.

    iptables_command = [
        'iptables',
        '-t', 'nat',
        '-D', 'PREROUTING',
        '-p', protocol,
        '--dport', str(host_port),
        '-j', 'DNAT',
        '--to-destination', f'{ip_at_creation}:{container_port}' # Use IP recorded at creation
    ]


    app.logger.info(f"Deleting NAT rule via iptables: {' '.join(shlex.quote(part) for part in iptables_command)}")

    # Execute the iptables command to delete the rule
    success_iptables, output = run_command(iptables_command, parse_json=False)

    if success_iptables:
        # If iptables deletion was successful, remove the record from the database
        db_success, db_message = remove_nat_rule_from_db(rule_id)
        message = f'已成功删除ID为 {rule_id} 的NAT规则。'
        if not db_success:
             message += f" 但从数据库移除记录失败: {db_message}"
             app.logger.error(f"Failed to remove NAT rule ID {rule_id} from DB after successful iptables: {db_message}")

        return jsonify({'status': 'success', 'message': message, 'output': output})
    else:
        # If iptables deletion failed, report the error and DO NOT remove from DB
        message = f'删除ID为 {rule_id} 的NAT规则失败: {output}'
        app.logger.error(f"iptables delete command failed for rule ID {rule_id}: {output}")
        # Keep the rule in DB so the user sees it's still there and can investigate/retry
        return jsonify({'status': 'error', 'message': message, 'output': output}), 500


def check_permissions():
    if os.geteuid() != 0:
        print("警告: 当前用户不是 root。执行 iptables 等命令可能需要 root 权限。")
        print("请考虑使用 'sudo python app.py' 运行此应用 (注意安全性风险)。")
    else:
        print("当前用户是 root。可以执行 iptables 等需要权限的命令。")


def main():
    if not os.path.exists(DATABASE_NAME):
        print(f"错误：数据库文件 '{DATABASE_NAME}' 未找到。")
        print("请先运行 'python init_db.py' 来初始化数据库。")
        sys.exit(1)

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='containers';")
        if not cursor.fetchone():
            print(f"错误：数据库表 'containers' 在 '{DATABASE_NAME}' 中未找到。")
            print("请确保 'python init_db.py' 已成功运行并创建了表结构。")
            print("您可以尝试删除旧的 incus_manager.db 文件然后重新运行 init_db.py。")
            sys.exit(1)

        # Basic check for containers table columns
        cursor.execute("PRAGMA table_info(containers);")
        columns_info = cursor.fetchall()
        column_names = [col[1] for col in columns_info]
        required_columns = ['incus_name', 'status', 'created_at', 'image_source']
        missing_columns = [col for col in required_columns if col not in column_names]
        if missing_columns:
            print(f"错误：数据库表 'containers' 缺少必需的列: {', '.join(missing_columns)}")
            print("请确保 'python init_db.py' 已成功运行并创建了正确的表结构。")
            print("您可以尝试删除旧的 incus_manager.db 文件然后重新运行 init_db.py。")
            sys.exit(1)

        # Check for unique index on incus_name in containers
        incus_name_cid = next((col[0] for col in columns_info if col[1] == 'incus_name'), None)
        if incus_name_cid is not None:
             cursor.execute(f"PRAGMA index_list(containers);")
             indexes = cursor.fetchall()
             is_unique = False
             for index in indexes:
                 if index[2] == 1:
                     cursor.execute(f"PRAGMA index_info('{index[1]}');")
                     index_cols = cursor.fetchall()
                     if len(index_cols) == 1 and index_cols[0][2] == 'incus_name':
                          is_unique = True
                          break
             if not is_unique:
                 print("警告：数据库表 'containers' 的 'incus_name' 列没有 UNIQUE 约束。这可能导致同步问题。")
                 print("建议删除旧的 incus_manager.db 文件然后重新运行 init_db.py 创建正确的表结构。")

        # Check for nat_rules table and columns
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nat_rules';")
        if not cursor.fetchone():
             print(f"错误：数据库表 'nat_rules' 在 '{DATABASE_NAME}' 中未找到。")
             print("请确保 'python init_db.py' 已成功运行并创建了表结构，包含 'nat_rules' 表。")
             sys.exit(1)

        cursor.execute("PRAGMA table_info(nat_rules);")
        nat_columns_info = cursor.fetchall()
        nat_column_names = [col[1] for col in nat_columns_info]
        required_nat_columns = ['container_name', 'host_port', 'container_port', 'protocol', 'ip_at_creation']
        missing_nat_columns = [col for col in required_nat_columns if col not in nat_column_names]
        if missing_nat_columns:
            print(f"错误：数据库表 'nat_rules' 缺少必需的列: {', '.join(missing_nat_columns)}")
            print("请确保 'python init_db.py' 已成功运行并创建了正确的表结构。")
            print("您可以尝试删除旧的 incus_manager.db 文件然后重新运行 init_db.py。")
            sys.exit(1)

        # Check for unique constraint on nat_rules (container_name, host_port, protocol)
        cursor.execute("PRAGMA index_list(nat_rules);")
        indexes = cursor.fetchall()
        unique_composite_index_exists = False
        for index_info in indexes:
            if index_info[2] == 1: # Check if it's unique
                index_name = index_info[1]
                cursor.execute(f"PRAGMA index_info('{index_name}');")
                index_cols = sorted([col[2] for col in cursor.fetchall()]) # Sort column names
                if index_cols == ['container_name', 'host_port', 'protocol']:
                     unique_composite_index_exists = True
                     break
        if not unique_composite_index_exists:
             print("警告：数据库表 'nat_rules' 可能缺少 UNIQUE (container_name, host_port, protocol) 约束。这可能导致重复规则记录。")
             print("建议删除旧的 incus_manager.db 文件然后重新运行 init_db.py 创建正确的表结构。")


    except sqlite3.Error as e:
        print(f"启动时数据库检查错误: {e}")
        sys.exit(1)
    finally:
        if conn:
            conn.close()

    try:
        subprocess.run(['incus', '--version'], check=True, capture_output=True, text=True, timeout=10)
        print("Incus 命令检查通过。")
    except FileNotFoundError:
         print("错误：'incus' 命令未找到。请确保 Incus 已正确安装并配置了 PATH。")
         sys.exit(1)
    except subprocess.CalledProcessError as e:
         print(f"错误：执行 'incus --version' 失败 (退出码 {e.returncode}): {e.stderr.strip()}")
         print("请检查 Incus 安装或权限问题。")
         sys.exit(1)
    except subprocess.TimeoutExpired:
         print("错误：执行 'incus --version' 超时。")
         sys.exit(1)
    except Exception as e:
         print(f"启动时 Incus 检查发生异常: {e}")
         sys.exit(1)

    try:
        subprocess.run(['iptables', '--version'], check=True, capture_output=True, text=True, timeout=5)
        print("iptables 命令检查通过。")
        check_permissions()
    except FileNotFoundError:
         print("警告：'iptables' 命令未找到。NAT 功能可能无法使用。")
    except subprocess.CalledProcessError as e:
         print(f"警告：执行 'iptables --version' 失败 (退出码 {e.returncode}): {e.stderr.strip()}")
         print("iptables 命令可能存在问题或权限不足。")
         check_permissions()
    except subprocess.TimeoutExpired:
         print("警告：执行 'iptables --version' 超时。")
         check_permissions()
    except Exception as e:
         print(f"启动时 iptables 检查发生异常: {e}")
         check_permissions()


    print("启动 Flask Web 服务器...")
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()
