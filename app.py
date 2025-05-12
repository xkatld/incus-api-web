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
        rv = cur.fetchall()
        conn.commit() # 对于select语句commit不是必须的，但为了函数通用性保留
    except sqlite3.Error as e:
        app.logger.error(f"数据库查询错误: {e}\nQuery: {query}\nArgs: {args}")
        rv = [] # 发生错误时返回空列表
    finally:
        if conn:
            conn.close()
    return (rv[0] if rv else None) if one else rv

# --- Incus 命令行辅助函数 ---
def run_incus_command(command_parts, parse_json=True):
    """
    执行 Incus 命令并返回结果。
    parse_json=True 时尝试解析 stdout 为 JSON。
    """
    try:
        # 设置 LC_ALL=C.UTF-8 确保 Incus 输出使用可预测的编码
        # 增加 LANG=C.UTF-8 也可能有帮助
        env_vars = os.environ.copy()
        env_vars['LC_ALL'] = 'C.UTF-8'
        env_vars['LANG'] = 'C.UTF-8'

        app.logger.info(f"Executing incus command: {' '.join(command_parts)}")
        result = subprocess.run(command_parts, capture_output=True, text=True, check=False, timeout=60, env=env_vars) # 增加超时时间到60秒

        if result.returncode != 0:
            error_message = result.stderr.strip() if result.stderr else result.stdout.strip()
            app.logger.error(f"Incus command failed: {' '.join(command_parts)}\nError: {error_message}")
            # 在错误情况下，尝试解析 stdout 是否包含部分 JSON (虽然不太可能对于 info)
            if parse_json and result.stdout.strip():
                 try:
                     # 有些命令即使失败也可能输出部分JSON或错误JSON结构
                     return False, {"error": error_message, "raw_output": result.stdout.strip()}
                 except json.JSONDecodeError:
                     pass # stdout不是JSON，忽略

            return False, f"命令执行失败: {error_message}"

        if parse_json:
            try:
                # 尝试更灵活的 JSON 解析，处理可能的 BOM 或其他前缀
                output_text = result.stdout.strip()
                # Remove potential leading BOM
                if output_text.startswith(u'\ufeff'):
                    output_text = output_text[1:]
                return True, json.loads(output_text)
            except json.JSONDecodeError as e:
                app.logger.error(f"Failed to parse JSON from incus: {result.stdout}\nError: {e}")
                # JSON解析失败，返回原始输出和错误
                return False, f"解析 Incus 输出为 JSON 失败: {e}\n原始输出: {result.stdout.strip()}"
        else:
            # 返回纯文本输出
            return True, result.stdout.strip()

    except FileNotFoundError:
        app.logger.error("Incus command not found. Is Incus installed and in PATH?")
        return False, "Incus 命令未找到。请确保 Incus 已安装并在系统 PATH 中。"
    except subprocess.TimeoutExpired:
        app.logger.error(f"Incus command timed out: {' '.join(command_parts)}")
        return False, "Incus 命令执行超时。"
    except Exception as e:
        app.logger.error(f"Exception running incus command: {e}")
        return False, f"执行 Incus 命令时发生异常: {str(e)}"


def sync_container_to_db(name, image_source, status, created_at_str):
    """将容器信息同步或添加到数据库"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Ensure created_at_str is a string or None
        created_at_to_db = str(created_at_str) if created_at_str is not None else datetime.datetime.now().isoformat()
        original_created_at_to_db = created_at_to_db # Keep original for logging if needed

        try:
            # Attempt to parse and format datetime, handle various possible formats from Incus output
            # Incus V5.21+ created_at is a string like "2024-02-21T08:08:10.123456789Z" or "2024-03-15T14:00:00Z"
            # incus info text format might be "2024/03/15 10:30 UTC" or similar
            # Database stores ISO format.

            # If it looks like Incus JSON ISO format (contains 'T' and timezone/Z)
            if isinstance(created_at_to_db, str) and 'T' in created_at_to_db and ('Z' in created_at_to_db or '+' in created_at_to_db or (len(created_at_to_db.split('T')[-1]) > 5 and created_at_to_db.split('T')[-1][0] in '+-')):
                 # Handle Incus JSON ISO format string
                 # Python's fromisoformat before 3.11 doesn't like more than 6 decimal places for microseconds
                 # And needs Z replaced with +00:00

                 # Replace Z with +00:00
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
                     second_part_and_tz = parts[1]
                     tz_part_match = re.search(r'[+-]\d{2}:?\d{2}$', second_part_and_tz)
                     if tz_part_match:
                          tz_part = tz_part_match.group(0)
                          second_part = second_part_and_tz[:second_part_and_tz.rfind(tz_part)]
                     else:
                          tz_part = ""
                          second_part = second_part_and_tz

                     if len(second_part) > 6:
                         second_part = second_part[:6]

                     created_at_to_db = parts[0] + '.' + second_part + tz_part
                 # No fractional seconds part but has timezone? Add .000000
                 elif re.search(r'[+-]\d{2}:?\d{2}$', created_at_to_db):
                      # Check if there's a timezone offset but no microseconds dot before it
                      if '.' not in created_at_to_db.split('T')[-1].split(re.search(r'[+-]', created_at_to_db.split('T')[-1]).group(0))[0]:
                           tz_part = re.search(r'[+-]\d{2}:?\d{2}$', created_at_to_db).group(0)
                           created_at_to_db = created_at_to_db.replace(tz_part, '.000000' + tz_part)


            # Validate the final ISO format string
            datetime.datetime.fromisoformat(created_at_to_db)

        except (ValueError, AttributeError, TypeError) as ve: # AttributeError if created_at_to_db is not a string
            app.logger.warning(f"无法精确解析 Incus 创建时间 '{original_created_at_to_db}' for {name} 为 ISO 格式 ({ve}). 将尝试使用数据库记录的原值或当前时间.")
            # If parsing Incus provided string fails, try to get old value from DB
            old_db_entry = query_db('SELECT created_at FROM containers WHERE incus_name = ?', [name], one=True)
            if old_db_entry and old_db_entry['created_at']:
                 # Validate the old DB value before using it
                 try:
                      datetime.datetime.fromisoformat(old_db_entry['created_at'])
                      created_at_to_db = old_db_entry['created_at']
                 except (ValueError, TypeError):
                      app.logger.warning(f"数据库记录的创建时间 '{old_db_entry['created_at']}' for {name} 也是无效 ISO 格式.")
                      created_at_to_db = datetime.datetime.now().isoformat() # Use current time if DB value is also invalid
            else:
                 # If DB also has no valid value, use current time
                 created_at_to_db = datetime.datetime.now().isoformat()


        cursor.execute('''
            INSERT INTO containers (incus_name, image_source, status, created_at, last_synced)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(incus_name) DO UPDATE SET
                image_source = excluded.image_source,
                status = excluded.status,
                created_at = excluded.created_at, -- Prioritize Incus provided or parsed time
                last_synced = CURRENT_TIMESTAMP
        ''', (name, image_source, status, created_at_to_db))
        conn.commit()
        #app.logger.info(f"Synced container {name} to DB.") # Avoid excessive logging
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 sync_container_to_db for {name}: {e}")
    finally:
        if conn:
            conn.close()

def remove_container_from_db(name):
    """从数据库中移除容器信息"""
    try:
        # Using query_db which handles conn/commit/close
        query_db('DELETE FROM containers WHERE incus_name = ?', [name])
        app.logger.info(f"从数据库中移除了容器: {name}")
    except sqlite3.Error as e:
         app.logger.error(f"数据库错误 remove_container_from_db for {name}: {e}")


# --- Flask 路由 ---

@app.route('/')
def index():
    """主页面，列出容器"""
    # Still use JSON format for list, as it's generally supported and structured
    success, containers_data = run_incus_command(['incus', 'list', '--format', 'json'])

    listed_containers = []
    db_containers_dict = {}
    incus_error = False
    incus_error_message = None

    # 1. Load existing containers from DB as fallback
    try:
        db_containers_dict = {row['incus_name']: dict(row) for row in query_db('SELECT * FROM containers')}
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

            # Get image_source
            image_source = 'N/A'
            item_config = item.get('config')
            if isinstance(item_config, dict):
                # Prioritize image.description, then volatile.cloud-init.instance-id, then image name from config
                image_source = item_config.get('image.description')
                if not image_source:
                     image_source = item_config.get('volatile.cloud-init.instance-id')
                if not image_source:
                     # Try to get the image alias or fingerprint prefix from config
                     image_alias = item_config.get('image.alias')
                     if image_alias:
                         image_source = f"Alias: {image_alias}"
                     else:
                         image_fingerprint = item_config.get('image.fingerprint')
                         if image_fingerprint and isinstance(image_fingerprint, str):
                              image_source = f"Fingerprint: {image_fingerprint[:12]}"
                if not image_source:
                     image_source = 'N/A'


            # Get created_at (Incus list JSON provides this)
            created_at_str = item.get('created_at', datetime.datetime.now().isoformat())

            # --- IP Address (Difficult to get reliably from 'list', better in 'info') ---
            # Incus list JSON state sometimes has network info, but structure varies.
            # Let's try to extract if available, but mark it as potentially missing.
            ip_address = 'N/A'
            container_state = item.get('state')
            if isinstance(container_state, dict):
                 network_info = container_state.get('network')
                 if isinstance(network_info, dict):
                     for iface_name, iface_data in network_info.items():
                         # Look for standard interface names
                         if (iface_name.startswith('eth') or iface_name.startswith('enp') or iface_name.startswith('ens')) and isinstance(iface_data, dict):
                             addresses = iface_data.get('addresses')
                             if isinstance(addresses, list):
                                 found_ip = False
                                 for addr_entry in addresses:
                                     if isinstance(addr_entry, dict):
                                         addr = addr_entry.get('address')
                                         family = addr_entry.get('family')
                                         scope = addr_entry.get('scope')
                                         # Prioritize global IPv4
                                         if addr and family == 'inet' and scope == 'global':
                                             ip_address = addr
                                             found_ip = True
                                             break
                                 if found_ip: break # Found a primary IP for this container

            # --- End IP Address extraction for list ---


            container_info = {
                'name': item_name,
                'status': item.get('status', 'Unknown'),
                'image_source': image_source,
                'ip': ip_address,
                'created_at': created_at_str,
            }
            listed_containers.append(container_info)
            # Sync current Incus state to DB
            sync_container_to_db(item_name, image_source, item.get('status', 'Unknown'), created_at_str)

        # Remove containers from DB that are no longer in Incus list
        for db_name in list(db_containers_dict.keys()):
            if db_name not in incus_container_names:
                remove_container_from_db(db_name)

    else: # Incus success but returned unexpected data format
        incus_error = True
        incus_error_message = f"Incus list 返回了未知数据格式: {containers_data}"
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
                # Find the first alias
                alias_entry = next((a for a in aliases if isinstance(a, dict) and a.get('name')), None) # Ensure alias dict has 'name'
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
    success, output = run_incus_command(['incus', 'launch', image, name], parse_json=False)
    if success:
        # Give Incus a moment to register the new container and start it
        time.sleep(3) # Increased sleep slightly

        # Try to get initial info via incus list (JSON is reliable here) to sync DB
        # Using list is often quicker and more reliable for basic status/created_at after launch
        _, list_output = run_incus_command(['incus', 'list', name, '--format', 'json'])

        created_at = datetime.datetime.now().isoformat() # Default if list fails or no created_at
        image_source_desc = image # Default image source description from input
        status_val = 'Pending' # Assume pending initially, list might update

        if isinstance(list_output, list) and len(list_output) > 0 and isinstance(list_output[0], dict):
             container_data = list_output[0]
             status_val = container_data.get('status', 'Unknown')
             created_at = container_data.get('created_at', created_at)
             # Get image source from list JSON config
             list_cfg = container_data.get('config')
             if isinstance(list_cfg, dict):
                  list_img_desc = list_cfg.get('image.description')
                  if list_img_desc: image_source_desc = list_img_desc
             app.logger.info(f"Successfully got list info for new container {name}.")
        else:
             # list command failed, use defaults or info text (optional, list is better)
             app.logger.warning(f"Failed to get list info for new container {name}. list output: {list_output}")
             # Fallback to incus info text parsing is possible but sync_container_to_db can handle defaults
             # Or rely on index sync later


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
    success, output = run_incus_command(commands[action], parse_json=False)

    if success:
        message = f'容器 {name} {action} 操作提交成功。'
        # Give the command some time to affect the state
        time.sleep(2) # Increased sleep

        if action == 'delete':
            remove_container_from_db(name)
            message = f'容器 {name} 已删除。'
        else:
            # After action, attempt to get updated status using incus list (JSON is reliable here)
            _, list_output = run_incus_command(['incus', 'list', name, '--format', 'json'])

            new_status_val = 'Unknown' # Default status if list fails or container not found
            db_image_source = 'N/A' # Default
            db_created_at = datetime.datetime.now().isoformat() # Default

            # Get existing info from DB to potentially keep image_source and created_at
            old_db_entry = query_db('SELECT image_source, created_at, status FROM containers WHERE incus_name = ?', [name], one=True)
            if old_db_entry:
                 db_image_source = old_db_entry['image_source']
                 db_created_at = old_db_entry['created_at']
                 new_status_val = old_db_entry['status'] # Start with old status

            if isinstance(list_output, list) and len(list_output) > 0 and isinstance(list_output[0], dict):
                container_data = list_output[0]
                # Update status from live Incus list output
                new_status_val = container_data.get('status', new_status_val)
                # Attempt to update image source and created_at from list JSON if available
                list_cfg = container_data.get('config')
                if isinstance(list_cfg, dict):
                     list_img_desc = list_cfg.get('image.description')
                     if list_img_desc: db_image_source = list_img_desc
                list_created_at = container_data.get('created_at')
                if list_created_at: db_created_at = list_created_at

                message = f'容器 {name} {action} 操作成功，新状态: {new_status_val}。'
            else:
                 # list command failed or container not found in list after action (e.g., stop might take time)
                 # Optimistically set status based on action if list failed
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

    # Split command string safely, handle potential quotes if needed for robustness
    try:
        command_parts = shlex.split(command_to_exec)
    except ValueError as e:
        return jsonify({'status': 'error', 'message': f'无效的命令格式: {e}'}), 400

    if not command_parts:
         return jsonify({'status': 'error', 'message': '执行的命令不能为空'}), 400


    # Incus exec does not output JSON by default
    success, output = run_incus_command(['incus', 'exec', name, '--'] + command_parts, parse_json=False)

    if success:
        return jsonify({'status': 'success', 'output': output})
    else:
        return jsonify({'status': 'error', 'output': output}), 500


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
        'created_at': db_info['created_at'] if db_info and 'created_at' in db_info and db_info['created_at'] else datetime.datetime.now().isoformat(),
        'architecture': 'N/A', # 尝试从文本解析
        'description': 'N/A', # 尝试从文本解析

        # 模拟 incus info --format json 中的 state 部分
        'state': {
            'status': db_info['status'] if db_info and 'status' in db_info else 'Unknown', # state里的状态和顶级状态一致
            'status_code': 0, # 文本输出没有status_code
            'network': {}, # 尝试从文本解析网络信息
            # 文本输出通常不包含 pid, cpu, memory, diskio 等详细实时状态，这些将缺失
            # 'pid': 0,
            # 'cpu': {},
            # 'memory': {},
            # 'disk': {},
            # 'processes': 0,
            # 'io': {},
            # 'limits': {},
            # 'usage': {},
        },

        # 文本输出通常不包含 config, devices, snapshots 的详细结构，这些将缺失或为空
        'config': {},
        'devices': {},
        'snapshots': [],
        'type': 'container', # 尝试从文本解析 Type
        'profiles': [], # 尝试从文本解析 Profiles
        # 'expanded_config': {}, # 文本输出没有这个
        # 'expanded_devices': {}, # 文本输出没有这个
        'ephemeral': False, # 尝试从文本解析
        'features': {}, # 文本输出没有这个

        'live_data_available': False, # 标记是否成功解析了 incus info 文本
        'message': '无法从 Incus 获取实时信息，数据主要来自数据库快照。' # 默认消息
        # 'raw_text_info': '' # 可选：包含原始文本输出用于调试
    }

    # If database doesn't have the container, it might mean it doesn't exist
    if not db_info:
         # Even if DB is empty for this name, try to get info from Incus in case it exists but wasn't synced
         app.logger.warning(f"Container {name} not found in DB. Attempting to get live info from Incus.")
         # Keep going to try incus info


    # 3. Attempt to execute incus info (plain text)
    # Not using --format json
    success_text, text_data = run_incus_command(['incus', 'info', name], parse_json=False)


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
                # Special handling for multi-line sections
                if line == 'Network state:':
                    current_section = 'Network state'
                    simulated_json_output['state']['network'] = {} # Initialize network dict
                elif line == 'Profiles:':
                    current_section = 'Profiles'
                    simulated_json_output['profiles'] = [] # Initialize profiles list
                # Add other multi-line sections here if needed
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
                         # If incus info Description provides a more detailed image description, use it
                         if value and value != 'N/A':
                            simulated_json_output['description'] = value
                            # Optionally: update image_source if this description is better than DB/default
                            # simulated_json_output['image_source'] = value # Decide whether to overwrite DB source
                         pass # Keep DB's image_source unless description is preferred
                    elif key == 'Created':
                         # Parsing Created time from text is fragile, keep DB's value
                         pass
                    elif key == 'Type':
                        simulated_json_output['type'] = value
                    elif key == 'Ephemeral':
                         simulated_json_output['ephemeral'] = (value.lower() == 'true')
                    # Add other simple fields if needed and parsable

            # Parse lines within the Network state section
            elif current_section == 'Network state':
                # Network line format is typically "- <interface> (<family>): <address>/<mask> (<scope>)"
                # Example: - eth0 (inet): 192.168.4.123/24 (global)
                # Example: - eth0 (inet6): fe80::.../64 (link)
                # Example: - eth0 (link): 00:16:3E:... (ether)
                network_match = re.match(r'^\s*-\s+([^ ]+)\s+\((inet|inet6|link)\):\s+([^ ]+)\s+\((global|link|host|ether)\)', line)
                if network_match:
                    iface_name = network_match.group(1)
                    addr_family = network_match.group(2)
                    address_with_mask = network_match.group(3)
                    addr_scope = network_match.group(4)

                    # Ensure simulated network structure exists for this interface
                    if iface_name not in simulated_json_output['state']['network']:
                         # Text info doesn't give interface state (up/down), assume up if addresses listed
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
                     # Handle potential hardware address line in network state section
                     # Example: - eth0 (link): 00:16:3E:... (ether)
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


        # --- Post-processing / Filling missing info ---
        # If incus info text parsing didn't find a status, keep the status from the database
        if simulated_json_output['status'] == 'Unknown' and db_info and 'status' in db_info:
             simulated_json_output['status'] = db_info['status']
             simulated_json_output['state']['status'] = db_info['status']


        # If incus info text parsing didn't find architecture, keep DB's or default
        if simulated_json_output['architecture'] == 'N/A' and db_info and 'architecture' in db_info: # Assuming DB might store architecture
             simulated_json_output['architecture'] = db_info['architecture']

        # Image source and created_at are more reliably from list JSON/DB sync, so they are populated from DB first
        # Keep the DB values unless text parsing found something definitively better (e.g., a full description)
        # simulated_json_output['image_source'] is already from DB or default

    else: # incus info (plain text) command failed
        incus_error_detail = text_data # text_data variable now contains the error message from run_incus_command
        simulated_json_output['message'] = f"获取容器 {name} 实时信息失败 (命令执行失败: {incus_error_detail}). 数据主要来自数据库快照。"
        simulated_json_output['live_data_available'] = False
        # Parsing fields remain at initial database values or defaults

    # If Incus info failed and DB didn't have the container either
    if not success_text and not db_info:
         simulated_json_output['message'] = f"获取容器 {name} 信息失败: 数据库中无记录且无法从 Incus 获取实时信息 ({incus_error_detail})."
         simulated_json_output['status'] = 'NotFound' # Simulate a status
         # Return 404 explicitly as the container likely doesn't exist
         return jsonify(simulated_json_output), 404


    # Return the constructed simulated JSON structure
    # If we reach here, either incus info succeeded (and parsing updated the struct)
    # or incus info failed but db_info was available (and the struct is populated from db_info/defaults)
    return jsonify(simulated_json_output)


def main():
    if not os.path.exists(DATABASE_NAME):
        print(f"错误：数据库文件 '{DATABASE_NAME}' 未找到。")
        print("请先运行 'python init_db.py' 来初始化数据库。")
        return

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
            return

        # Check if containers table has required columns (at least incus_name, status, created_at, image_source)
        cursor.execute("PRAGMA table_info(containers);")
        columns_info = cursor.fetchall()
        column_names = [col[1] for col in columns_info]
        required_columns = ['incus_name', 'status', 'created_at', 'image_source']
        missing_columns = [col for col in required_columns if col not in column_names]
        if missing_columns:
            print(f"错误：数据库表 'containers' 缺少必需的列: {', '.join(missing_columns)}")
            print("请确保 'python init_db.py' 已成功运行并创建了正确的表结构。")
            print("您可以尝试删除旧的 incus_manager.db 文件然后重新运行 init_db.py。")
            return

        # Check if incus_name column has a UNIQUE constraint
        incus_name_cid = next((col[0] for col in columns_info if col[1] == 'incus_name'), None)
        if incus_name_cid is not None:
             cursor.execute(f"PRAGMA index_list(containers);")
             indexes = cursor.fetchall()
             is_unique = False
             for index in indexes:
                 index_name = index[1]
                 cursor.execute(f"PRAGMA index_info('{index_name}');")
                 index_cols = cursor.fetchall()
                 if len(index_cols) == 1 and index_cols[0][2] == 'incus_name' and index[2] == 1: # cid, name, cid_name_in_index, primary key (isunique)
                     is_unique = True
                     break
             if not is_unique:
                 print("警告：数据库表 'containers' 的 'incus_name' 列没有 UNIQUE 约束。这可能导致同步问题。")
                 print("建议删除旧的 incus_manager.db 文件然后重新运行 init_db.py 创建正确的表结构。")


    except sqlite3.Error as e:
        print(f"启动时数据库检查错误: {e}")
        return
    finally:
        if conn:
            conn.close()

    # Ensure Incus command exists and is executable (basic check)
    try:
        subprocess.run(['incus', '--version'], check=True, capture_output=True, text=True)
        print("Incus 命令检查通过。")
    except FileNotFoundError:
         print("错误：'incus' 命令未找到。请确保 Incus 已正确安装并配置了 PATH。")
         return
    except subprocess.CalledProcessError as e:
         print(f"错误：执行 'incus --version' 失败: {e.stderr.strip()}")
         print("请检查 Incus 安装或权限问题。")
         return
    except Exception as e:
         print(f"启动时 Incus 检查发生异常: {e}")
         return


    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()
