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
        app.logger.error(f"Exception running command: {e}")
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
        app.logger.info(f"从数据库中移除了容器: {name}")
    except sqlite3.Error as e:
         app.logger.error(f"数据库错误 remove_container_from_db for {name}: {e}")


def get_container_ip(container_name):
    success, output = run_incus_command(['info', container_name], parse_json=False)

    if not success:
        app.logger.warning(f"无法获取容器 {container_name} 的 incus info 输出: {output}")
        return None

    lines = output.splitlines()
    ip_address = None
    in_network_state_section = False

    for line in lines:
        line_stripped = line.strip()

        if line_stripped == 'Network state:':
            in_network_state_section = True
            continue

        if in_network_state_section:
            if not line.startswith(' ') and line_stripped.endswith(':') and line_stripped != 'Network state:':
                in_network_state_section = False
                continue

            ip_match = re.match(r'^\s+inet:\s*([^ ]+)\s+\(global\)', line)

            if ip_match:
                ip_with_mask = ip_match.group(1)
                ip_address = ip_with_mask.split('/')[0]
                app.logger.info(f"成功从 incus info 解析出容器 {container_name} 的全局 IPv4 地址: {ip_address}")
                return ip_address

    app.logger.warning(f"在容器 {container_name} 的 incus info 输出中无法找到全局 IPv4 地址 (用于NAT等功能)。")
    return None


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
                'ip': 'N/A (DB info)',
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

            ip_address = 'N/A'
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
                                         if addr and family == 'inet' and scope == 'global':
                                             ip_address = addr
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

        for name, data in db_containers_dict.items():
            listed_containers.append({
                'name': name,
                'status': data.get('status', 'Unknown (from DB)'),
                'image_source': data.get('image_source', 'N/A (from DB)'),
                'ip': 'N/A (DB info)',
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
        time.sleep(5)

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
        'stop': ['incus', 'stop', name, '--force'],
        'restart': ['incus', 'restart', name, '--force'],
        'delete': ['incus', 'delete', name, '--force'],
    }
    if action not in commands:
        return jsonify({'status': 'error', 'message': '无效的操作'}), 400

    timeout_val = 60
    if action == 'delete': timeout_val = 120

    success, output = run_command(commands[action], parse_json=False, timeout=timeout_val)

    if success:
        message = f'容器 {name} {action} 操作提交成功。'
        time.sleep(3)

        if action == 'delete':
            remove_container_from_db(name)
            message = f'容器 {name} 已删除。'
        else:
            _, list_output = run_incus_command(['list', name, '--format', 'json'], timeout=10)

            new_status_val = 'Unknown'
            db_image_source = 'N/A'
            db_created_at = None

            old_db_entry = query_db('SELECT image_source, created_at, status FROM containers WHERE incus_name = ?', [name], one=True)
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
                 app.logger.warning(f"Failed to get updated status for {name} after {action}. list output: {list_output}")

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
        command_parts = shlex.split(command_to_exec)
    except ValueError as e:
        return jsonify({'status': 'error', 'message': f'无效的命令格式: {e}'}), 400

    if not command_parts:
         return jsonify({'status': 'error', 'message': '执行的命令不能为空'}), 400


    success, output = run_incus_command(['exec', name, '--'] + command_parts, parse_json=False)

    if success:
        return jsonify({'status': 'success', 'output': output})
    else:
        return jsonify({'status': 'error', 'output': output, 'message': '命令执行失败'}), 500


@app.route('/container/<name>/info')
def container_info(name):
    db_info = query_db('SELECT * FROM containers WHERE incus_name = ?', [name], one=True)

    simulated_json_output = {
        'name': name,
        'status': db_info['status'] if db_info and 'status' in db_info else 'Unknown',
        'status_code': 0,
        'image_source': db_info['image_source'] if db_info and 'image_source' in db_info and db_info['image_source'] else 'N/A',
        'created_at': db_info['created_at'] if db_info and 'created_at' in db_info and db_info['created_at'] else None,

        'architecture': 'N/A',
        'description': 'N/A',

        'state': {
            'status': db_info['status'] if db_info and 'status' in db_info else 'Unknown',
            'status_code': 0,
            'network': {},
        },

        'config': {},
        'devices': {},
        'snapshots': [],
        'type': 'container',
        'profiles': [],
        'ephemeral': False,

        'live_data_available': False,
        'message': '无法从 Incus 获取实时信息，数据主要来自数据库快照。'
    }

    if not db_info:
         app.logger.warning(f"Container {name} not found in DB. Attempting to get live info from Incus.")


    success_text, text_data = run_incus_command(['info', name], parse_json=False)


    if success_text:
        simulated_json_output['live_data_available'] = True
        simulated_json_output['message'] = '数据主要来自 Incus (通过文本解析)，部分来自数据库。'

        lines = text_data.splitlines()
        current_section = None

        for line in lines:
            line = line.strip()
            if not line:
                 current_section = None
                 continue

            if line.endswith(':'):
                if line == 'Network state:':
                    current_section = 'Network state'
                    simulated_json_output['state']['network'] = {}
                elif line == 'Profiles:':
                    current_section = 'Profiles'
                    simulated_json_output['profiles'] = []
                elif line == 'Devices:':
                     current_section = 'Devices'
                elif line == 'Snapshots:':
                     current_section = 'Snapshots'
                elif line == 'Config:':
                     current_section = 'Config'

                else:
                    current_section = None

                continue

            if current_section is None:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()

                    if key == 'Status':
                        simulated_json_output['status'] = value
                        simulated_json_output['state']['status'] = value
                        status_code_map = {
                             'Running': 100, 'Stopped': 101, 'Frozen': 102,
                             'Starting': 103, 'Stopping': 104, 'Aborting': 105,
                             'Error': 106, 'Created': 107, 'Pending': 108
                        }
                        simulated_json_output['status_code'] = status_code_map.get(value, 0)
                        simulated_json_output['state']['status_code'] = simulated_json_output['status_code']

                    elif key == 'Architecture':
                        simulated_json_output['architecture'] = value
                    elif key == 'Description':
                         if value and value != 'N/A':
                            simulated_json_output['description'] = value
                         pass
                    elif key == 'Created':
                         pass
                    elif key == 'Type':
                        simulated_json_output['type'] = value
                    elif key == 'Ephemeral':
                         simulated_json_output['ephemeral'] = (value.lower() == 'true')

            elif current_section == 'Network state':
                network_addr_match = re.match(r'^\s+(eth\d+|enp\d+s?\d+|ens\d+s?\d+):\s*|\s+inet:\s*([^ ]+)\s+\(global\)', line)
                if network_addr_match:
                     if network_addr_match.group(2):
                        ip_with_mask = network_addr_match.group(2)
                        if 'eth0' not in simulated_json_output['state']['network']:
                            simulated_json_output['state']['network']['eth0'] = {'addresses': [], 'state': 'up', 'hwaddr': 'N/A'}

                        ip_address_only = ip_with_mask.split('/')[0]
                        if not any(addr_entry['address'] == ip_address_only for addr_entry in simulated_json_output['state']['network']['eth0']['addresses']):
                             simulated_json_output['state']['network']['eth0']['addresses'].append({
                                'address': ip_address_only,
                                'family': 'inet',
                                'netmask': ip_with_mask.split('/')[-1] if '/' in ip_with_mask else '',
                                'scope': 'global'
                             })
                             if simulated_json_output['ip'] == 'N/A':
                                 simulated_json_output['ip'] = ip_address_only


    if simulated_json_output['status'] == 'Unknown' and db_info and 'status' in db_info:
         simulated_json_output['status'] = db_info['status']
         simulated_json_output['state']['status'] = db_info['status']
         if simulated_json_output['status_code'] == 0:
             status_code_map = {
                  'Running': 100, 'Stopped': 101, 'Frozen': 102,
                  'Starting': 103, 'Stopping': 104, 'Aborting': 105,
                  'Error': 106, 'Created': 107, 'Pending': 108
             }
             simulated_json_output['status_code'] = status_code_map.get(simulated_json_output['status'], 0)
             simulated_json_output['state']['status_code'] = simulated_json_output['status_code']


    if simulated_json_output['architecture'] == 'N/A' and db_info and 'architecture' in db_info and db_info['architecture'] != 'N/A':
         simulated_json_output['architecture'] = db_info['architecture']


    if not success_text and not db_info:
         simulated_json_output['message'] = f"获取容器 {name} 信息失败: 数据库中无记录且无法从 Incus 获取实时信息 ({text_data if not success_text else '未知错误'})."
         simulated_json_output['status'] = 'NotFound'
         return jsonify(simulated_json_output), 404

    info_ip = get_container_ip(name)
    if info_ip:
         simulated_json_output['ip'] = info_ip


    return jsonify(simulated_json_output)


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

    _, list_output = run_incus_command(['list', name, '--format', 'json'], timeout=5)

    container_status = 'Unknown'
    if isinstance(list_output, list) and len(list_output) > 0 and isinstance(list_output[0], dict):
         container_status = list_output[0].get('status', 'Unknown')
    else:
         db_info = query_db('SELECT status FROM containers WHERE incus_name = ?', [name], one=True)
         if db_info:
             container_status = db_info['status']
         else:
            return jsonify({'status': 'error', 'message': f'容器 {name} 不存在或无法获取其状态。'}), 404

    if container_status != 'Running':
         return jsonify({'status': 'error', 'message': f'容器 {name} 必须处于 Running 状态才能添加 NAT 规则 (当前状态: {container_status})。'}), 400

    container_ip = get_container_ip(name)

    if not container_ip:
         return jsonify({'status': 'error', 'message': f'无法获取容器 {name} 的 IP 地址。请确保容器正在运行且已分配 IP。'}), 500

    iptables_command = [
        'iptables',
        '-t', 'nat',
        '-A', 'PREROUTING',
        '-p', protocol,
        '--dport', str(host_port),
        '-j', 'DNAT',
        '--to-destination', f'{container_ip}:{container_port}'
    ]

    app.logger.info(f"Adding NAT rule: {' '.join(shlex.quote(part) for part in iptables_command)}")

    success, output = run_command(iptables_command, parse_json=False)

    if success:
        message = f'已成功为容器 {name} 添加 NAT 规则: 主机端口 {host_port}/{protocol} 转发到容器 IP {container_ip} 端口 {container_port}。'
        return jsonify({'status': 'success', 'message': message, 'output': output})
    else:
        message = f'添加 NAT 规则失败: {output}'
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
