# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for
import subprocess # 用于执行命令行
import json       # 用于解析 Incus 的 JSON 输出 (虽然info不用了, list还需要)
import sqlite3
import datetime
import os # 引入 os 模块
import time # 引入 time 模块
import re # 引入 re 模块用于正则表达式解析文本
import shlex # 用于安全分割命令字符串
import sys # 用于检查用户权限

app = Flask(__name__)
DATABASE_NAME = 'incus_manager.db' # 确保和 init_db.py 中的一致

# --- 数据库辅助函数 ---
def get_db_connection():
    """获取数据库连接"""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def query_db(query, args=(), one=False):
    """执行数据库查询"""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(query, args)
        # For INSERT/UPDATE/DELETE, commit is needed
        if not query.strip().upper().startswith('SELECT'):
             conn.commit()
        rv = cur.fetchall()
    except sqlite3.Error as e:
        app.logger.error(f"数据库查询错误: {e}\nQuery: {query}\nArgs: {args}")
        rv = [] # 发生错误时返回空列表
        # Rollback any potential partial transaction on error
        if conn:
             conn.rollback()
    finally:
        if conn:
            conn.close()
    return (rv[0] if rv else None) if one else rv

# --- Incus/System Command Helper ---
def run_command(command_parts, parse_json=True, timeout=60):
    """
    执行命令行命令 (Incus 或其他如 iptables) 并返回结果。
    parse_json=True 时尝试解析 stdout 为 JSON。
    """
    try:
        # 设置 LC_ALL=C.UTF-8 确保 Incus/系统输出使用可预测的编码
        env_vars = os.environ.copy()
        env_vars['LC_ALL'] = 'C.UTF-8'
        env_vars['LANG'] = 'C.UTF-8'

        app.logger.info(f"Executing command: {' '.join(shlex.quote(part) for part in command_parts)}") # Use shlex.quote for logging commands safely
        result = subprocess.run(command_parts, capture_output=True, text=True, check=False, timeout=timeout, env=env_vars)

        if result.returncode != 0:
            error_message = result.stderr.strip() if result.stderr else result.stdout.strip()
            app.logger.error(f"Command failed (Exit code {result.returncode}): {' '.join(shlex.quote(part) for part in command_parts)}\nError: {error_message}")
            # In case of failure, also check if stdout contains any useful info
            full_output = f"STDOUT:\n{result.stdout.strip()}\nSTDERR:\n{result.stderr.strip()}"
            return False, f"命令执行失败 (退出码 {result.returncode}): {error_message}\n完整输出:\n{full_output}"

        if parse_json:
            try:
                output_text = result.stdout.strip()
                if output_text.startswith(u'\ufeff'): # Remove potential leading BOM
                    output_text = output_text[1:]
                return True, json.loads(output_text)
            except json.JSONDecodeError as e:
                app.logger.error(f"Failed to parse JSON from command output: {result.stdout}\nError: {e}")
                return False, f"解析命令输出为 JSON 失败: {e}\n原始输出: {result.stdout.strip()}"
        else:
            # Return pure text output
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

# --- Specific Incus Helper Functions using run_command ---
def run_incus_command(command_parts, parse_json=True, timeout=60):
    """Helper specifically for incus commands."""
    return run_command(['incus'] + command_parts, parse_json, timeout)


def sync_container_to_db(name, image_source, status, created_at_str):
    """将容器信息同步或添加到数据库"""
    # Use query_db for DB operations
    try:
        # Ensure created_at_str is a string or None and handle potential Incus formats
        created_at_to_db = str(created_at_str) if created_at_str is not None else None # Prefer None over current time initially if Incus didn't provide

        if created_at_to_db:
            original_created_at_to_db = created_at_to_db # Keep original for logging if needed
            try:
                # Handle Incus JSON ISO format string (e.g., "2024-03-15T14:00:00Z", "2024-02-21T08:08:10.123456789Z")
                # Replace Z with +00:00 if present
                if created_at_to_db.endswith('Z'):
                   created_at_to_db = created_at_to_db[:-1] + '+00:00'

                # Handle timezone formats like -HHMM (convert to -HH:MM for fromisoformat)
                tz_match_hhmm = re.search(r'([+-])(\d{4})$', created_at_to_db)
                if tz_match_hhmm:
                    sign = tz_match_hhmm.group(1)
                    hhmm = tz_match_hhmm.group(2)
                    created_at_to_db = created_at_to_db[:-4] + f"{sign}{hhmm[:2]}:{hhmm[2:]}"

                # Truncate microseconds if too long (more than 6 digits)
                parts = created_at_to_db.split('.')
                if len(parts) > 1:
                    time_tz_part = parts[1]
                    # Find the start of the timezone part (either + or - followed by digits)
                    tz_start_match = re.search(r'[+-]\d', time_tz_part)
                    if tz_start_match:
                         micro_part = time_tz_part[:tz_start_match.start()]
                         tz_part = time_tz_part[tz_start_match.start():]
                         if len(micro_part) > 6:
                            micro_part = micro_part[:6]
                         time_tz_part = micro_part + tz_part
                    else: # No explicit timezone after microseconds
                        if len(time_tz_part) > 6:
                            time_tz_part = time_tz_part[:6]

                    created_at_to_db = parts[0] + '.' + time_tz_part
                # If no fractional seconds part but has timezone, fromisoformat might need .000000
                elif re.search(r'[+-]\d{2}:?\d{2}$', created_at_to_db):
                     # Check if there's a timezone offset but no microseconds dot before it
                     # This is complex, simplify: if it looks like datetime + timezone, add .000000
                     # Check if the segment after 'T' and before timezone contains a dot for seconds
                     time_segment = created_at_to_db.split('T')[-1]
                     if '.' not in time_segment.split(re.search(r'[+-]', time_segment).group(0))[0]:
                           tz_part = re.search(r'[+-]\d{2}:?\d{2}$', created_at_to_db).group(0)
                           # Ensure we don't add .000000 if it already has milliseconds/microseconds
                           if not '.' in created_at_to_db:
                              created_at_to_db = created_at_to_db.replace(tz_part, '.000000' + tz_part)


                # Validate the final ISO format string
                datetime.datetime.fromisoformat(created_at_to_db) # This will raise error if format is wrong

            except (ValueError, AttributeError, TypeError) as ve: # AttributeError if created_at_to_db is not a string
                app.logger.warning(f"无法精确解析 Incus 创建时间 '{original_created_at_to_db}' for {name} 为 ISO 格式 ({ve}). 将尝试使用数据库记录的原值或当前时间.")
                # If parsing Incus provided string fails, try to get old value from DB
                old_db_entry = query_db('SELECT created_at FROM containers WHERE incus_name = ?', [name], one=True)
                if old_db_entry and old_db_entry['created_at']:
                     # Validate the old DB value before using it
                     try:
                          datetime.datetime.fromisoformat(old_db_entry['created_at'])
                          created_at_to_db = old_db_entry['created_at'] # Use old DB value if valid
                     except (ValueError, TypeError):
                          app.logger.warning(f"数据库记录的创建时间 '{old_db_entry['created_at']}' for {name} 也是无效 ISO 格式.")
                          created_at_to_db = datetime.datetime.now().isoformat() # Use current time if DB value is also invalid
                else:
                     # If DB also has no valid value or no record, use current time
                     created_at_to_db = datetime.datetime.now().isoformat()

        else: # Incus did not provide created_at, try to get from DB or use current time
             old_db_entry = query_db('SELECT created_at FROM containers WHERE incus_name = ?', [name], one=True)
             if old_db_entry and old_db_entry['created_at']:
                 # Validate the old DB value before using it
                 try:
                      datetime.datetime.fromisoformat(old_db_entry['created_at'])
                      created_at_to_db = old_db_entry['created_at'] # Use old DB value if valid
                 except (ValueError, TypeError):
                      app.logger.warning(f"数据库记录的创建时间 '{old_db_entry['created_at']}' for {name} 也是无效 ISO 格式.")
                      created_at_to_db = datetime.datetime.now().isoformat() # Use current time if DB value is also invalid
             else:
                  created_at_to_db = datetime.datetime.now().isoformat() # Use current time if no Incus time and no valid DB time


        query_db('''
            INSERT INTO containers (incus_name, image_source, status, created_at, last_synced)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(incus_name) DO UPDATE SET
                image_source = excluded.image_source,
                status = excluded.status,
                created_at = excluded.created_at, -- Prioritize Incus provided or parsed time
                last_synced = CURRENT_TIMESTAMP
        ''', (name, image_source, status, created_at_to_db))
        # app.logger.info(f"Synced container {name} to DB with status {status}.") # Avoid excessive logging
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 sync_container_to_db for {name}: {e}")


def remove_container_from_db(name):
    """从数据库中移除容器信息"""
    try:
        query_db('DELETE FROM containers WHERE incus_name = ?', [name])
        app.logger.info(f"从数据库中移除了容器: {name}")
    except sqlite3.Error as e:
         app.logger.error(f"数据库错误 remove_container_from_db for {name}: {e}")


def get_container_ip(container_name):
    """
    尝试获取容器的主要 IPv4 地址 (global scope)。
    解析 incus info 的文本输出。
    返回 IP 地址字符串或 None。
    """
    success, output = run_incus_command(['incus', 'info', container_name], parse_json=False)

    if not success:
        app.logger.warning(f"无法获取容器 {container_name} 的 incus info 输出: {output}")
        return None

    # Parse the text output
    lines = output.splitlines()
    current_section = None
    ip_address = None

    for line in lines:
        line = line.strip()
        if not line:
            current_section = None
            continue

        if line == 'Network state:':
            current_section = 'Network state'
            continue # Move to the next line for content

        if current_section == 'Network state':
            # Look for lines like: - eth0 (inet): 192.168.4.123/24 (global)
            # We prioritize global IPv4 addresses
            network_match = re.match(r'^\s*-\s+[^ ]+\s+\(inet\):\s+([^ ]+)\s+\(global\)', line)
            if network_match:
                ip_with_mask = network_match.group(1)
                ip_address = ip_with_mask.split('/')[0]
                app.logger.info(f"找到容器 {container_name} 的 IPv4 地址: {ip_address}")
                return ip_address # Found a global IPv4, return it immediately


    # If loop finishes without finding a global IPv4
    app.logger.warning(f"无法找到容器 {container_name} 的全局 IPv4 地址。")
    return None


# --- Flask 路由 ---

@app.route('/')
def index():
    """主页面，列出容器"""
    # Use JSON format for list, as it's generally supported and structured
    success, containers_data = run_incus_command(['incus', 'list', '--format', 'json'])

    listed_containers = []
    db_containers_dict = {}
    incus_error = False
    incus_error_message = None

    # 1. Load existing containers from DB as fallback
    try:
        db_containers_dict = {row['incus_name']: dict(row) for row in query_db('SELECT * FROM containers')}
        # app.logger.info(f"Loaded {len(db_containers_dict)} containers from DB.") # Avoid excessive logging
    except sqlite3.OperationalError as e:
        app.logger.error(f"数据库表 'containers' 可能不存在: {e}. 请运行 init_db.py.")
        incus_error = True
        incus_error_message = f"数据库错误：容器表未找到，请运行 init_db.py。原始错误: {e}"
        # If DB has issues, render error template directly
        return render_template('index.html',
                               containers=[],
                               images=[],
                               incus_error=(incus_error, incus_error_message),
                               image_error=(True, "无法加载可用镜像列表.")) # Assume image list also fails without DB


    # 2. Get real-time list from Incus and sync
    if not success:
        incus_error = True
        incus_error_message = containers_data # containers_data contains error message if success is False
        app.logger.warning(f"无法从 Incus 获取容器列表 ({incus_error_message})，尝试从数据库加载。")
        # Incus failed, but DB has data, use DB data to populate listed_containers
        for name, data in db_containers_dict.items():
            listed_containers.append({
                'name': name,
                'status': data.get('status', 'Unknown (from DB)'),
                'image_source': data.get('image_source', 'N/A (from DB)'),
                # IP address is not reliably available in 'list' JSON output, better in 'info' or 'state'
                'ip': 'N/A (DB info)', # IP is hard to get from list view, will get it in detail view
                'created_at': data.get('created_at', 'N/A (from DB)')
            })

    elif isinstance(containers_data, list): # Incus success and returned a list
        incus_container_names = set()
        for item in containers_data:
            if not isinstance(item, dict) or 'name' not in item:
                app.logger.warning(f"Skipping invalid item in containers_data: {item}")
                continue

            item_name = item['name']
            incus_container_names.add(item_name)

            # Get image_source from Incus list JSON config
            image_source = 'N/A'
            item_config = item.get('config')
            if isinstance(item_config, dict):
                # Prioritize image.description, then image name from config
                image_source = item_config.get('image.description')
                # Fallback to alias or fingerprint if description missing
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


            # Get created_at from Incus list JSON
            created_at_str = item.get('created_at') # Incus provides this, use it

            # --- IP Address (Attempt to get from state if available, fallback to N/A) ---
            # Incus list JSON state *can* contain network info, but it's often less reliable
            # than parsing 'incus info' text, especially for filtering global IPv4.
            # Let's use the more reliable `get_container_ip` helper if status is Running.
            ip_address = 'N/A'
            container_status = item.get('status', 'Unknown')
            if container_status == 'Running':
                 # Call helper function to get the IP address
                 # NOTE: This calls `incus info` for *each* running container in the list view,
                 # which might be slow for many containers. A better approach for large lists
                 # might be to only show IP in the info modal or add a specific endpoint to get IPs.
                 # For now, do it for each running container.
                 container_ip = get_container_ip(item_name)
                 if container_ip:
                      ip_address = container_ip


            container_info = {
                'name': item_name,
                'status': container_status, # Use status from Incus list
                'image_source': image_source,
                'ip': ip_address, # Use IP from get_container_ip helper
                'created_at': created_at_str, # Use created_at from Incus list
            }
            listed_containers.append(container_info)
            # Sync current Incus state to DB (status, image_source, created_at are from live Incus)
            sync_container_to_db(item_name, image_source, container_status, created_at_str)


        # Remove containers from DB that are no longer in Incus list
        # Get current names from DB *after* syncing/updating existing ones
        current_db_names = {row['incus_name'] for row in query_db('SELECT incus_name FROM containers')}
        for db_name in current_db_names:
            if db_name not in incus_container_names:
                remove_container_from_db(db_name)

    else: # Incus success but returned unexpected data format
        incus_error = True
        incus_error_message = f"Incus list 返回了未知数据格式或错误结构: {containers_data}"
        app.logger.error(incus_error_message)
        # Incus failed, but DB has data, use DB data to populate listed_containers
        for name, data in db_containers_dict.items():
            listed_containers.append({
                'name': name,
                'status': data.get('status', 'Unknown (from DB)'),
                'image_source': data.get('image_source', 'N/A (from DB)'),
                'ip': 'N/A (DB info)',
                'created_at': data.get('created_at', 'N/A (from DB)')
            })


    # Get available images (still using JSON format as it's generally supported for image list)
    success_img, images_data = run_incus_command(['incus', 'image', 'list', '--format', 'json'])
    available_images = []
    image_error = False
    image_error_message = None
    if success_img and isinstance(images_data, list):
        for img in images_data:
            if not isinstance(img, dict): continue

            alias_name = None
            aliases = img.get('aliases')
            if isinstance(aliases, list) and aliases:
                # Find the first alias with a name
                alias_entry = next((a for a in aliases if isinstance(a, dict) and a.get('name')), None)
                if alias_entry:
                     alias_name = alias_entry.get('name')

            if not alias_name:
                # Fallback to fingerprint prefix if no alias found
                fingerprint = img.get('fingerprint')
                alias_name = fingerprint[:12] if isinstance(fingerprint, str) else 'unknown_image'

            description_props = img.get('properties')
            description = 'N/A'
            if isinstance(description_props, dict):
                description = description_props.get('description', 'N/A')

            # Add image to list
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

    # Incus launch command does not output JSON by default
    success, output = run_incus_command(['incus', 'launch', image, name], parse_json=False, timeout=120) # Increased timeout for launch

    if success:
        # Give Incus a moment to register the new container and start it
        # It's better to poll incus list/info until status changes, but sleep is simpler for demo
        time.sleep(5) # Increased sleep significantly after launch

        # Try to get initial info via incus list (JSON is reliable here) to sync DB
        # Using list is often quicker and more reliable for basic status/created_at after launch
        _, list_output = run_incus_command(['incus', 'list', name, '--format', 'json'])

        created_at = None # Default if list fails or no created_at
        image_source_desc = image # Default image source description from input
        status_val = 'Pending' # Assume pending initially, list might update

        if isinstance(list_output, list) and len(list_output) > 0 and isinstance(list_output[0], dict):
             container_data = list_output[0]
             status_val = container_data.get('status', 'Unknown')
             created_at = container_data.get('created_at') # Use Incus provided created_at
             # Get image source from list JSON config
             list_cfg = container_data.get('config')
             if isinstance(list_cfg, dict):
                  list_img_desc = list_cfg.get('image.description')
                  if list_img_desc: image_source_desc = list_img_desc # Prefer description from Incus
             app.logger.info(f"Successfully got list info for new container {name}.")
        else:
             # list command failed, use defaults
             app.logger.warning(f"Failed to get list info for new container {name}. list output: {list_output}")

        # Sync the obtained info to the database
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

    # Actions like start/stop/delete don't output JSON by default
    # Set timeout based on action - delete can take longer
    timeout_val = 60
    if action == 'delete': timeout_val = 120

    success, output = run_incus_command(commands[action], parse_json=False, timeout=timeout_val)

    if success:
        message = f'容器 {name} {action} 操作提交成功。'
        # Give the command some time to affect the state before querying list again
        time.sleep(3) # Increased sleep slightly

        if action == 'delete':
            remove_container_from_db(name)
            message = f'容器 {name} 已删除。'
        else:
            # After action, attempt to get updated status using incus list (JSON is reliable here)
            # Use a small timeout for the list command itself
            _, list_output = run_incus_command(['incus', 'list', name, '--format', 'json'], timeout=10)

            new_status_val = 'Unknown' # Default status if list fails or container not found
            db_image_source = 'N/A' # Default
            db_created_at = None # Default

            # Get existing info from DB to potentially keep image_source and created_at if list fails
            old_db_entry = query_db('SELECT image_source, created_at, status FROM containers WHERE incus_name = ?', [name], one=True)
            if old_db_entry:
                 db_image_source = old_db_entry['image_source']
                 db_created_at = old_db_entry['created_at']
                 new_status_val = old_db_entry['status'] # Start with old status from DB

            if isinstance(list_output, list) and len(list_output) > 0 and isinstance(list_output[0], dict):
                container_data = list_output[0]
                # Update status from live Incus list output
                new_status_val = container_data.get('status', new_status_val)
                 # Only update image_source and created_at if Incus provided them in the list output
                list_cfg = container_data.get('config')
                if isinstance(list_cfg, dict):
                     list_img_desc = list_cfg.get('image.description')
                     if list_img_desc: db_image_source = list_img_desc # Prefer description from Incus
                list_created_at = container_data.get('created_at')
                if list_created_at: db_created_at = list_created_at # Prefer created_at from Incus

                message = f'容器 {name} {action} 操作成功，新状态: {new_status_val}。'
            else:
                 # list command failed or container not found in list after action (e.g., stop might take time)
                 # Optimistically set status based on action if list failed, use DB value as base
                 if action == 'start': new_status_val = 'Running'
                 elif action == 'stop': new_status_val = 'Stopped'
                 elif action == 'restart': new_status_val = 'Running' # Restart finishes in Running state
                 message = f'容器 {name} {action} 操作提交成功，但无法获取最新状态（list命令失败或容器状态未立即更新）。'
                 app.logger.warning(f"Failed to get updated status for {name} after {action}. list output: {list_output}")

            # Sync potentially updated status, image source, created_at to DB
            sync_container_to_db(name, db_image_source, new_status_val, db_created_at)


        return jsonify({'status': 'success', 'message': message})
    else:
        return jsonify({'status': 'error', 'message': f'容器 {name} {action} 操作失败: {output}'}), 500


@app.route('/container/<name>/exec', methods=['POST'])
def exec_command(name):
    command_to_exec = request.form.get('command')
    if not command_to_exec:
        return jsonify({'status': 'error', 'message': '执行的命令不能为空'}), 400

    # Split command string safely, handle potential quotes
    try:
        command_parts = shlex.split(command_to_exec)
    except ValueError as e:
        return jsonify({'status': 'error', 'message': f'无效的命令格式: {e}'}), 400

    if not command_parts:
         return jsonify({'status': 'error', 'message': '执行的命令不能为空'}), 400


    # Incus exec does not output JSON by default
    # Use run_command directly
    success, output = run_incus_command(['exec', name, '--'] + command_parts, parse_json=False)

    if success:
        return jsonify({'status': 'success', 'output': output})
    else:
        # Output contains stderr/stdout and error message from run_command
        return jsonify({'status': 'error', 'output': output, 'message': '命令执行失败'}), 500


@app.route('/container/<name>/info')
def container_info(name):
    """
    获取容器详细信息。
    通过解析 incus info 命令的纯文本输出来模拟 Incus info JSON 输出的部分结构。
    """

    # 1. 从数据库获取基本信息作为补充和fallback
    db_info = query_db('SELECT * FROM containers WHERE incus_name = ?', [name], one=True)

    # 2. 初始化一个字典，模拟 Incus JSON 输出的部分结构
    # 用数据库信息填充可信度高的字段
    simulated_json_output = {
        'name': name,
        # 从DB获取初始状态
        'status': db_info['status'] if db_info and 'status' in db_info else 'Unknown',
        'status_code': 0, # 文本输出通常没有status_code, 默认为0
        # 从DB获取 image_source 和 created_at
        'image_source': db_info['image_source'] if db_info and 'image_source' in db_info and db_info['image_source'] else 'N/A',
        'created_at': db_info['created_at'] if db_info and 'created_at' in db_info and db_info['created_at'] else None, # None if DB has no value

        'architecture': 'N/A', # Attempt to parse from text
        'description': 'N/A', # Attempt to parse from text (Incus info text description is often the image description)

        # Simulate incus info --format json state part
        'state': {
            'status': db_info['status'] if db_info and 'status' in db_info else 'Unknown', # state status matches top-level status
            'status_code': 0, # No status_code in text output
            'network': {}, # Attempt to parse network info from text
            # text output typically doesn't include detailed real-time state like pid, cpu, memory, diskio
        },

        # text output typically doesn't include full config, devices, snapshots structure
        'config': {}, # Empty or minimal config based on text if parsable
        'devices': {}, # Empty
        'snapshots': [], # Empty
        'type': 'container', # Attempt to parse Type from text
        'profiles': [], # Attempt to parse Profiles from text
        'ephemeral': False, # Attempt to parse Ephemeral from text

        'live_data_available': False, # Flag whether parsing incus info text was successful
        'message': '无法从 Incus 获取实时信息，数据主要来自数据库快照。' # Default message
        # 'raw_text_info': '' # Optional: include raw text output for debugging
    }

    # If database doesn't have the container, it might mean it doesn't exist
    if not db_info:
         app.logger.warning(f"Container {name} not found in DB. Attempting to get live info from Incus.")


    # 3. Attempt to execute incus info (plain text)
    success_text, text_data = run_incus_command(['info', name], parse_json=False)


    # 4. If incus info command successful, parse text and update simulated JSON structure
    if success_text:
        simulated_json_output['live_data_available'] = True
        simulated_json_output['message'] = '数据主要来自 Incus (通过文本解析)，部分来自数据库。'
        # simulated_json_output['raw_text_info'] = text_data # Optional: include raw text output for debugging

        lines = text_data.splitlines()
        current_section = None # Track current text paragraph being parsed

        # Iterate through each line to parse
        for line in lines:
            line = line.strip()
            if not line:
                 current_section = None # Empty line ends a paragraph
                 continue

            # Check for new main paragraph titles (ending with colon)
            if line.endswith(':'):
                # Handle specific multi-line sections
                if line == 'Network state:':
                    current_section = 'Network state'
                    simulated_json_output['state']['network'] = {} # Initialize network dict for parsed data
                elif line == 'Profiles:':
                    current_section = 'Profiles'
                    simulated_json_output['profiles'] = [] # Initialize profiles list for parsed data
                # Add other multi-line sections here if needed (e.g., Devices, Snapshots)
                # For Devices/Snapshots, parsing text might be complex, leaving empty for now.
                elif line == 'Devices:':
                     current_section = 'Devices' # Mark section, but simple text parsing might just skip its content
                elif line == 'Snapshots:':
                     current_section = 'Snapshots' # Mark section
                elif line == 'Config:':
                     current_section = 'Config' # Mark section

                else:
                    current_section = None # Other colon-ending lines are usually single-line main properties, next line parses value

                continue # Processed title line, move to next line for content

            # Parse single-line main properties (not within any multi-line section)
            if current_section is None:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()

                    if key == 'Status':
                        simulated_json_output['status'] = value
                        simulated_json_output['state']['status'] = value # Update state status too
                        # Attempt to map status string to a code (very rough guess)
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
                         # If incus info Description provides a value (not N/A), use it
                         if value and value != 'N/A':
                            simulated_json_output['description'] = value
                            # Optionally: update image_source if this description is clearly better
                            # simulated_json_output['image_source'] = value # Decide whether to overwrite DB source
                         pass # Keep DB's image_source unless description is preferred
                    elif key == 'Created':
                         # Parsing Created time from text is fragile (e.g., "2024/03/15 10:30 UTC"), keep DB's ISO value if available
                         # If DB value is missing or invalid, we might try parsing this text format
                         # For now, rely on DB/list JSON for created_at and skip text parsing here
                         pass
                    elif key == 'Type':
                        simulated_json_output['type'] = value
                    elif key == 'Ephemeral':
                         simulated_json_output['ephemeral'] = (value.lower() == 'true')
                    # Add other simple fields if needed and parsable

            # Parse lines within the Network state section
            elif current_section == 'Network state':
                # Network line format is typically "- <interface> (<family>): <address>/<mask> (<scope>)" or "- <interface> (link): <hwaddr> (ether)"
                # Example: - eth0 (inet): 192.168.4.123/24 (global)
                # Example: - eth0 (inet6): fe80::.../64 (link)
                # Example: - eth0 (link): 00:16:3E:... (ether)

                # Match address lines
                network_addr_match = re.match(r'^\s*-\s+([^ ]+)\s+\((inet|inet6)\):\s+([^ ]+)\s+\((global|link|host)\)', line)
                if network_addr_match:
                    iface_name = network_addr_match.group(1)
                    addr_family = network_addr_match.group(2)
                    address_with_mask = network_addr_match.group(3)
                    addr_scope = network_addr_match.group(4)

                    # Ensure simulated network structure exists for this interface
                    if iface_name not in simulated_json_output['state']['network']:
                        # Text info doesn't give interface state (up/down) directly, assume up if addresses listed
                        simulated_json_output['state']['network'][iface_name] = {'addresses': [], 'state': 'up', 'hwaddr': 'N/A'}

                    # Extract IP address without mask
                    ip_address_only = address_with_mask.split('/')[0]

                    # Add address information
                    simulated_json_output['state']['network'][iface_name]['addresses'].append({
                        'address': ip_address_only,
                        'family': addr_family,
                        'netmask': address_with_mask.split('/')[-1] if '/' in address_with_mask else '', # Add netmask if present
                        'scope': addr_scope
                    })
                else:
                     # Match hardware address line
                     hwaddr_match = re.match(r'^\s*-\s+([^ ]+)\s+\(link\):\s+([^ ]+)\s+\(ether\)', line)
                     if hwaddr_match:
                         iface_name = hwaddr_match.group(1)
                         hw_address = hwaddr_match.group(2)
                         if iface_name not in simulated_json_output['state']['network']:
                            simulated_json_output['state']['network'][iface_name] = {'addresses': [], 'state': 'up', 'hwaddr': hw_address}
                         else:
                             simulated_json_output['state']['network'][iface_name]['hwaddr'] = hw_address


            # Parse lines within the Profiles section
            elif current_section == 'Profiles':
               profile_match = re.match(r'^\s*-\s+([^ ]+)', line)
               if profile_match:
                  simulated_json_output['profiles'].append(profile_match.group(1))

            # Add parsing for Config, Devices, Snapshots sections if needed (complex)
            # elif current_section == 'Config':
            #     # Example config line: security.nesting: "true"
            #     config_match = re.match(r'^\s*([^:]+):\s*(.+)', line)
            #     if config_match:
            #         key = config_match.group(1).strip()
            #         value_str = config_match.group(2).strip()
            #         # Attempt to convert string value to boolean/number if appropriate
            #         if value_str.lower() == 'true': value = True
            #         elif value_str.lower() == 'false': value = False
            #         elif value_str.isdigit(): value = int(value_str)
            #         else: value = value_str.strip('"') # Remove quotes if present
            #         simulated_json_output['config'][key] = value


    # --- Post-processing / Filling missing info ---
    # If incus info text parsing didn't find a status, keep the status from the database
    if simulated_json_output['status'] == 'Unknown' and db_info and 'status' in db_info:
         simulated_json_output['status'] = db_info['status']
         simulated_json_output['state']['status'] = db_info['status']
         # Update status code based on this DB status if the status code is still 0 (default)
         if simulated_json_output['status_code'] == 0:
             status_code_map = {
                  'Running': 100, 'Stopped': 101, 'Frozen': 102,
                  'Starting': 103, 'Stopping': 104, 'Aborting': 105,
                  'Error': 106, 'Created': 107, 'Pending': 108
             }
             simulated_json_output['status_code'] = status_code_map.get(simulated_json_output['status'], 0)
             simulated_json_output['state']['status_code'] = simulated_json_output['status_code']


    # If incus info text parsing didn't find architecture, keep DB's or default
    # (Assuming DB might store architecture, though not currently populated)
    if simulated_json_output['architecture'] == 'N/A' and db_info and 'architecture' in db_info and db_info['architecture'] != 'N/A':
         simulated_json_output['architecture'] = db_info['architecture']

    # Image source and created_at are more reliably from list JSON/DB sync, so they are populated from DB first
    # Keep the DB values unless text parsing found something definitively better (e.g., a full description)
    # simulated_json_output['image_source'] is already from DB or default
    # simulated_json_output['created_at'] is already from DB or None


    # If Incus info failed and DB didn't have the container either
    if not success_text and not db_info:
         simulated_json_output['message'] = f"获取容器 {name} 信息失败: 数据库中无记录且无法从 Incus 获取实时信息 ({text_data if not success_text else '未知错误'})."
         simulated_json_output['status'] = 'NotFound' # Simulate a status
         # Return 404 explicitly as the container likely doesn't exist
         return jsonify(simulated_json_output), 404


    # Return the constructed simulated JSON structure
    # If we reach here, either incus info succeeded (and parsing updated the struct)
    # or incus info failed but db_info was available (and the struct is populated from db_info/defaults)
    return jsonify(simulated_json_output)


@app.route('/container/<name>/add_nat_rule', methods=['POST'])
def add_nat_rule(name):
    host_port = request.form.get('host_port')
    container_port = request.form.get('container_port')
    protocol = request.form.get('protocol') # 'tcp' or 'udp'

    # Validate input
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

    # Check if the container is running to get its IP
    db_info = query_db('SELECT status FROM containers WHERE incus_name = ?', [name], one=True)
    if not db_info:
        # Container not found in DB, try to get live status from Incus
        _, list_output = run_incus_command(['incus', 'list', name, '--format', 'json'], timeout=5)
        if isinstance(list_output, list) and len(list_output) > 0 and isinstance(list_output[0], dict):
             container_status = list_output[0].get('status', 'Unknown')
        else:
             return jsonify({'status': 'error', 'message': f'容器 {name} 不存在或无法获取其状态。'}), 404
    else:
         container_status = db_info['status']

    if container_status != 'Running':
         return jsonify({'status': 'error', 'message': f'容器 {name} 必须处于 Running 状态才能添加 NAT 规则 (当前状态: {container_status})。'}), 400

    # Get the container's IP address
    container_ip = get_container_ip(name)

    if not container_ip:
         return jsonify({'status': 'error', 'message': f'无法获取容器 {name} 的 IP 地址。请确保容器正在运行且已分配 IP。'}), 500

    # Construct the iptables command
    # iptables -t nat -A PREROUTING -p <protocol> --dport <host_port> -j DNAT --to-destination <container_ip>:<container_port>
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

    # Execute the iptables command
    # WARNING: This requires the user running the Flask app to have sufficient permissions (e.g., root)
    # A safer production system would use a more secure method to execute privileged commands.
    success, output = run_command(iptables_command, parse_json=False)

    if success:
        message = f'已成功为容器 {name} 添加 NAT 规则: 主机端口 {host_port}/{protocol} 转发到容器 IP {container_ip} 端口 {container_port}。'
        return jsonify({'status': 'success', 'message': message, 'output': output})
    else:
        # output already contains error details from run_command
        message = f'添加 NAT 规则失败: {output}'
        return jsonify({'status': 'error', 'message': message, 'output': output}), 500


def check_permissions():
    """检查当前运行脚本的用户是否是 root."""
    # On Unix-like systems, root user has uid 0
    if os.geteuid() != 0:
        print("警告: 当前用户不是 root。执行 iptables 等命令可能需要 root 权限。")
        print("请考虑使用 'sudo python app.py' 运行此应用 (注意安全性风险)。")
        # sys.exit(1) # Optional: exit if not root
    else:
        print("当前用户是 root。可以执行 iptables 等需要权限的命令。")


def main():
    # Check database existence and structure
    if not os.path.exists(DATABASE_NAME):
        print(f"错误：数据库文件 '{DATABASE_NAME}' 未找到。")
        print("请先运行 'python init_db.py' 来初始化数据库。")
        sys.exit(1) # Exit if database is missing

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Check if containers table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='containers';")
        if not cursor.fetchone():
            print(f"错误：数据库表 'containers' 在 '{DATABASE_NAME}' 中未找到。")
            print("请确保 'python init_db.py' 已成功运行并创建了表结构。")
            # Suggest deleting old file and rerunning init_db.py
            print("您可以尝试删除旧的 incus_manager.db 文件然后重新运行 init_db.py。")
            sys.exit(1) # Exit if table is missing

        # Check if containers table has required columns (at least incus_name, status, created_at, image_source)
        cursor.execute("PRAGMA table_info(containers);")
        columns_info = cursor.fetchall()
        column_names = [col[1] for col in columns_info]
        required_columns = ['incus_name', 'status', 'created_at', 'image_source'] # added image_source
        missing_columns = [col for col in required_columns if col not in column_names]
        if missing_columns:
            print(f"错误：数据库表 'containers' 缺少必需的列: {', '.join(missing_columns)}")
            print("请确保 'python init_db.py' 已成功运行并创建了正确的表结构。")
            print("您可以尝试删除旧的 incus_manager.db 文件然后重新运行 init_db.py。")
            sys.exit(1) # Exit if columns are missing

        # Check if incus_name column has a UNIQUE constraint (warning only)
        incus_name_cid = next((col[0] for col in columns_info if col[1] == 'incus_name'), None)
        if incus_name_cid is not None:
             cursor.execute(f"PRAGMA index_list(containers);")
             indexes = cursor.fetchall()
             is_unique = False
             for index in indexes:
                 # Index list returns (seq, name, unique, origin, partial)
                 if index[2] == 1: # Check if the index is unique
                     cursor.execute(f"PRAGMA index_info('{index[1]}');")
                     index_cols = cursor.fetchall()
                     # Index info returns (seqno, cid, name)
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

    # Ensure Incus command exists and is executable (basic check)
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

    # Check if iptables command exists and warn about permissions
    try:
        subprocess.run(['iptables', '--version'], check=True, capture_output=True, text=True, timeout=5)
        print("iptables 命令检查通过。")
        check_permissions() # Check root permission after confirming iptables exists
    except FileNotFoundError:
         print("警告：'iptables' 命令未找到。NAT 功能可能无法使用。")
    except subprocess.CalledProcessError as e:
         print(f"警告：执行 'iptables --version' 失败 (退出码 {e.returncode}): {e.stderr.strip()}")
         print("iptables 命令可能存在问题或权限不足。")
         check_permissions() # Still check root permission
    except subprocess.TimeoutExpired:
         print("警告：执行 'iptables --version' 超时。")
         check_permissions() # Still check root permission
    except Exception as e:
         print(f"启动时 iptables 检查发生异常: {e}")
         check_permissions() # Still check root permission


    print("启动 Flask Web 服务器...")
    # Consider running with waitress or gunicorn for production
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()
