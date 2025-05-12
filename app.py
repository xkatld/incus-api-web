--- START OF FILE app.txt ---

# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for
import subprocess # 用于执行命令行
import json       # 用于解析 Incus 的 JSON 输出 (虽然info不用了，list还需要)
import sqlite3
import datetime
import os # 引入 os 模块
import time # 引入 time 模块
import re # 引入 re 模块用于正则表达式解析文本

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
                if output_text.startswith(u'\ufeff'): # 处理BOM
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
        created_at_to_db = str(created_at_str) if created_at_str else datetime.datetime.now().isoformat()
        try:
            # 尝试解析并格式化日期时间，处理 Incus 输出的各种可能格式
            # Incus V5.21+ created_at is a string like "2024-02-21T08:08:10.123456789Z" or "2024-03-15T14:00:00Z"
            # incus info text format might be "2024/03/15 10:30 UTC" or similar
            # Database stores ISO format.
            
            # If it looks like Incus V5.21+ JSON output format
            if 'T' in created_at_to_db and ('Z' in created_at_to_db or '+' in created_at_to_db or '-' in created_at_to_db.split('T')[-1]):
                 # Handle Incus JSON ISO format string
                 # Python's fromisoformat before 3.11 doesn't like more than 6 decimal places for microseconds
                 if 'Z' in created_at_to_db:
                    created_at_to_db = created_at_to_db.replace("Z", "+00:00")

                 parts = created_at_to_db.split('.')
                 if len(parts) > 1:
                    second_part_and_tz = parts[1]
                    tz_part = ""
                    # Find timezone separator (+ or -)
                    tz_idx = -1
                    if '+' in second_part_and_tz:
                        tz_idx = second_part_and_tz.find('+')
                    elif '-' in second_part_and_tz: # Could be date part or timezone
                         # Check if '-' is likely a timezone offset (-HH:MM or -HHMM)
                         tz_match = re.search(r'-(\d{2}:?\d{2}|\d{4})$', second_part_and_tz)
                         if tz_match:
                              tz_idx = second_part_and_tz.rfind('-') # Find the last '-'
                         else: # Could be negative microseconds? Unlikely but handle
                              pass # Keep full microseconds if no timezone found
                    
                    if tz_idx != -1:
                        tz_part = second_part_and_tz[tz_idx:]
                        second_part = second_part_and_tz[:tz_idx]
                    else:
                         second_part = second_part_and_tz

                    # Truncate microseconds to 6 digits
                    if len(second_part) > 6:
                        second_part = second_part[:6]

                    created_at_to_db = parts[0] + '.' + second_part + tz_part
                 # No fractional seconds part? Add .000000
                 elif '+' in created_at_to_db or ('-' in created_at_to_db and len(created_at_to_db.split('-')[-1].split('T')[-1]) > 4): # Ensure it's a TZ part, not just date separator
                      # Check if there's a timezone offset like +00:00 or -0500 but no microseconds
                      tz_match = re.search(r'[+-](\d{2}:?\d{2}|\d{4})$', created_at_to_db)
                      if tz_match and '.' not in created_at_to_db.split('T')[-1].split(tz_match.group(0)[0])[0]: # No dot before TZ separator
                           created_at_to_db = created_at_to_db.replace(tz_match.group(0), '.000000' + tz_match.group(0))


            # Validate the final ISO format string (or near-ISO)
            datetime.datetime.fromisoformat(created_at_to_db)

        except (ValueError, AttributeError, TypeError) as ve: # AttributeError if created_at_to_db is None
            app.logger.warning(f"无法精确解析 Incus 创建时间 '{created_at_str}' for {name} 为 ISO 格式 ({ve}). 将使用数据库记录的原值或当前时间.")
            # 如果解析 Incus 提供的字符串失败，尝试从数据库获取旧值
            old_db_entry = query_db('SELECT created_at FROM containers WHERE incus_name = ?', [name], one=True)
            if old_db_entry and old_db_entry['created_at']:
                 created_at_to_db = old_db_entry['created_at']
            else:
                 # 如果数据库也没有有效值，则使用当前时间
                 created_at_to_db = datetime.datetime.now().isoformat()


        cursor.execute('''
            INSERT INTO containers (incus_name, image_source, status, created_at, last_synced)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(incus_name) DO UPDATE SET
                image_source = excluded.image_source,
                status = excluded.status,
                created_at = excluded.created_at, -- 优先使用 Incus 提供的或解析后的时间
                last_synced = CURRENT_TIMESTAMP
        ''', (name, image_source, status, created_at_to_db))
        conn.commit()
        #app.logger.info(f"Synced container {name} to DB.") # 避免日志过多
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 sync_container_to_db for {name}: {e}")
    finally:
        if conn:
            conn.close()

def remove_container_from_db(name):
    """从数据库中移除容器信息"""
    try:
        query_db('DELETE FROM containers WHERE incus_name = ?', [name])
        app.logger.info(f"从数据库中移除了容器: {name}")
    except sqlite3.Error as e:
         app.logger.error(f"数据库错误 remove_container_from_db for {name}: {e}")


# --- Flask 路由 ---

@app.route('/')
def index():
    """主页面，列出容器"""
    # 仍然使用 JSON 格式获取列表，因为更稳定且包含创建时间等信息
    success, containers_data = run_incus_command(['incus', 'list', '--format', 'json'])

    listed_containers = []
    db_containers_dict = {}
    incus_error_message = None

    # 1. 从数据库加载现有容器作为 fallback
    try:
        db_containers_dict = {row['incus_name']: dict(row) for row in query_db('SELECT * FROM containers')}
    except sqlite3.OperationalError as e:
        app.logger.error(f"数据库表 'containers' 可能不存在: {e}. 请运行 init_db.py.")
        incus_error_message = f"数据库错误：容器表未找到，请运行 init_db.py。原始错误: {e}"
        # 如果数据库都出问题，直接返回错误模板
        return render_template('index.html', 
                               containers=[], 
                               images=[],
                               incus_error=(True, incus_error_message))


    # 2. 从 Incus 获取实时列表并同步
    if not success:
        incus_error_message = containers_data # containers_data contains error message if success is False
        app.logger.warning(f"无法从 Incus 获取容器列表 ({incus_error_message})，尝试从数据库加载。")
        # Incus 失败，但数据库有数据，使用数据库数据填充 listed_containers
        for name, data in db_containers_dict.items():
            listed_containers.append({
                'name': name,
                'status': data.get('status', 'Unknown (from DB)'),
                'image_source': data.get('image_source', 'N/A (from DB)'),
                # IP地址在 list JSON 输出中并不总是直接 available，通常在 info 或 state 里
                'ip': 'N/A (DB info)', # IP 从列表页难获取，详情页获取
                'created_at': data.get('created_at', 'N/A (from DB)')
            })

    elif isinstance(containers_data, list): # Incus 成功且返回了列表
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
        incus_error_message = f"Incus list 返回了未知数据格式: {containers_data}"
        app.logger.error(incus_error_message)
        # Incus 失败，但数据库有数据，使用数据库数据填充 listed_containers
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
    image_error_message = None
    if success_img and isinstance(images_data, list):
        for img in images_data:
            if not isinstance(img, dict): continue

            alias_name = None
            aliases = img.get('aliases')
            if isinstance(aliases, list) and aliases:
                # Find the first alias
                alias_entry = next((a for a in aliases if isinstance(a, dict)), None)
                if alias_entry:
                     alias_name = alias_entry.get('name')

            if not alias_name:
                fingerprint = img.get('fingerprint')
                alias_name = fingerprint[:12] if isinstance(fingerprint, str) else 'unknown_image'

            description_props = img.get('properties')
            description = 'N/A'
            if isinstance(description_props, dict):
                description = description_props.get('description', 'N/A')

            # Skip images without aliases or description that look like base images without useful names
            # Example: images from private remotes might just have fingerprint aliases.
            # Let's just add all found images for now.
            available_images.append({'name': alias_name, 'description': f"{alias_name} ({description})"})
    else:
        image_error_message = images_data if not success_img else 'Invalid image data format from Incus.'
        app.logger.error(f"获取镜像列表失败: {image_error_message}")


    return render_template('index.html',
                           containers=listed_containers,
                           images=available_images,
                           incus_error=(not success, incus_error_message),
                           image_error=(not success_img, image_error_message))


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

        # Try to get initial info via plain text info command to sync DB
        _, info_text = run_incus_command(['incus', 'info', name], parse_json=False)

        created_at = datetime.datetime.now().isoformat() # Default if parsing fails
        image_source_desc = image # Default image source description
        status_val = 'Pending' # Assume pending initially, text parsing might update

        # Attempt to parse key info from text output
        if info_text and isinstance(info_text, str):
            lines = info_text.splitlines()
            for line in lines:
                line = line.strip()
                if line.startswith('Status:'):
                    status_val = line.split(':', 1)[1].strip() if ':' in line else status_val
                # Parsing Created time from text is fragile, sticking to DB/default
                # Parsing image.description/alias from text config is also hard
                # Description line might give image description
                elif line.startswith('Description:'):
                     image_source_desc = line.split(':', 1)[1].strip() if ':' in line else image_source_desc
                     if image_source_desc == 'N/A': # If description is N/A, use the launch image name
                          image_source_desc = image


        # Use the image name from launch command as a fallback image source description
        if image_source_desc == 'N/A':
            image_source_desc = f"Launched from: {image}"


        # If parsing status failed, try getting it from list (JSON format)
        if status_val == 'Pending':
             _, list_output = run_incus_command(['incus', 'list', name, '--format', 'json'])
             if isinstance(list_output, list) and len(list_output) > 0 and isinstance(list_output[0], dict):
                  status_val = list_output[0].get('status', 'Unknown')
                  # Also attempt to get created_at from list json
                  created_at = list_output[0].get('created_at', created_at)
                  # And image source description from list json config
                  list_cfg = list_output[0].get('config')
                  if isinstance(list_cfg, dict):
                       list_img_desc = list_cfg.get('image.description')
                       if list_img_desc: image_source_desc = list_img_desc


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
    # Simple split might break commands with spaces in arguments (e.g., echo "hello world")
    # For more robust parsing, consider shlex.split
    import shlex
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
    通过解析 incus info 命令的纯文本输出来模拟 JSON 输出结构。
    """

    # 1. 尝试执行 incus info (纯文本)
    # 不使用 --format json
    success_text, text_data = run_incus_command(['incus', 'info', name], parse_json=False)

    # 2. 从数据库获取基本信息作为补充和fallback
    db_info = query_db('SELECT * FROM containers WHERE incus_name = ?', [name], one=True)

    # 3. 初始化一个字典，模拟 Incus JSON 输出的结构
    # 用数据库信息填充可信度高的字段
    simulated_json_output = {
        'name': name,
        # 从DB或解析文本获取的状态
        'status': db_info['status'] if db_info else 'Unknown',
        'status_code': 0, # 文本输出没有status_code, 默认为0
        'image_source': db_info['image_source'] if db_info and db_info['image_source'] else 'N/A',
        'created_at': db_info['created_at'] if db_info and db_info['created_at'] else datetime.datetime.now().isoformat(),
        'architecture': 'N/A', # 尝试从文本解析
        'description': 'N/A', # 尝试从文本解析

        # 模拟 incus info --format json 中的 state 部分
        'state': {
            'status': db_info['status'] if db_info else 'Unknown', # state里的状态和顶级状态一致
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
        'type': 'container', # 文本输出有Type: container
        # 'profiles': [], # 文本输出有Profiles:
        # 'expanded_config': {}, # 文本输出没有这个
        # 'expanded_devices': {}, # 文本输出没有这个
        # 'ephemeral': False, # 文本输出没有
        # 'features': {}, # 文本输出没有

        'live_data_available': False, # 标记是否成功解析了 incus info 文本
        'message': '无法从 Incus 获取实时信息，数据来自数据库快照。' # 默认消息
        # 'raw_text_info': '' # 可选：包含原始文本输出用于调试
    }

    # 如果数据库没有找到容器，返回错误
    if not db_info:
         simulated_json_output['message'] = f"获取容器 {name} 信息失败: 数据库中无记录且无法从 Incus 获取实时信息。"
         simulated_json_output['status'] = 'NotFound' # 模拟一个状态
         # http status code should be 404, but jsonify might return 200. Let's return 404 explicitly.
         return jsonify(simulated_json_output), 404


    # 4. 如果 incus info 命令成功，开始解析文本并更新模拟的 JSON 结构
    if success_text:
        simulated_json_output['live_data_available'] = True
        simulated_json_output['message'] = '数据主要来自 Incus (通过文本解析)，部分来自数据库。'
        # simulated_json_output['raw_text_info'] = text_data # 可选：包含原始文本输出

        lines = text_data.splitlines()
        current_section = None # 跟踪当前解析的文本段落

        # 遍历每一行进行解析
        for line in lines:
            line = line.strip()
            if not line:
                 current_section = None # 空行表示段落结束
                 continue

            # 检查是否是新的主段落标题 (以冒号结尾)
            if line.endswith(':'):
                # 特殊处理网络状态，它有子行
                if line == 'Network state:':
                    current_section = 'Network state'
                # 特殊处理 Profiles:
                elif line == 'Profiles:':
                    current_section = 'Profiles'
                # 可以添加其他需要特殊处理的多行段落
                else:
                    current_section = None # 其他冒号结尾的单行主属性，如下一行会解析其值

                continue # 处理完标题行，进入下一行解析内容

            # 解析单行主属性 (不在任何多行段落内)
            if current_section is None:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()

                    if key == 'Status':
                        simulated_json_output['status'] = value
                        simulated_json_output['state']['status'] = value # 更新 state 中的状态
                    elif key == 'Architecture':
                        simulated_json_output['architecture'] = value
                    elif key == 'Description':
                         # 如果 incus info 的 Description 提供了更详细的镜像描述，使用它
                         if value and value != 'N/A':
                            simulated_json_output['description'] = value
                            # 也可以考虑用这个更新 image_source，但 DB 的 image_source 可能更可靠
                            # simulated_json_output['image_source'] = value
                         else:
                             # 如果文本描述是 N/A，保留数据库或默认的 image_source
                             pass
                    # Created 时间解析复杂，依赖DB，不在这里覆盖
                    # elif key == 'Created':
                    #    pass # 暂时不解析文本创建时间
                    elif key == 'Type':
                        simulated_json_output['type'] = value
                    # Add other simple fields if needed and parsable
                    # elif key == 'PID': # PID通常在state里，info文本不一定有
                    #     try: simulated_json_output['state']['pid'] = int(value)
                    #     except ValueError: pass

            # 解析网络状态段落内的行
            elif current_section == 'Network state':
                # 网络行的格式通常是 "- <interface> (<family>): <address>/<mask> (<scope>)"
                # 示例文本行: - eth0 (inet): 192.168.4.123/24 (global)
                # 示例文本行: - eth0 (inet6): fe80::.../64 (link)
                # 示例文本行: - eth0 (link): 00:16:3E:... (ether)
                network_match = re.match(r'^\s*-\s+([^ ]+)\s+\((inet|inet6|link)\):\s+([^ ]+)\s+\((global|link|host|ether)\)', line)
                if network_match:
                    iface_name = network_match.group(1)
                    addr_family = network_match.group(2)
                    address_with_mask = network_match.group(3)
                    addr_scope = network_match.group(4)

                    # 确保模拟的 network 结构存在该接口
                    if iface_name not in simulated_json_output['state']['network']:
                        simulated_json_output['state']['network'][iface_name] = {'addresses': [], 'state': 'up'} # state: 'up' 是推测的，文本info不直接提供

                    # 添加地址信息
                    simulated_json_output['state']['network'][iface_name]['addresses'].append({
                        'address': address_with_mask.split('/')[0], # 提取IP地址，去掉掩码
                        'family': addr_family,
                        'scope': addr_scope
                    })

            # 解析 Profiles 段落内的行 (如果需要)
            # elif current_section == 'Profiles':
            #    profile_match = re.match(r'^\s*-\s+([^ ]+)', line)
            #    if profile_match:
            #       simulated_json_output.setdefault('profiles', []).append(profile_match.group(1))


        # --- 后处理 / 填充缺失信息 ---
        # 如果从文本解析到的状态与数据库状态不同，优先使用解析到的状态
        # 如果解析到的 image_source (来自 Description) 比数据库的 N/A 更好，也可以考虑更新
        # 但为了稳定，image_source 和 created_at 优先保留来自 DB 的值

        # 如果文本解析成功获取到状态，更新顶级和 state 中的状态
        if 'status' in simulated_json_output and simulated_json_output['status'] != (db_info['status'] if db_info else 'Unknown'):
             simulated_json_output['state']['status'] = simulated_json_output['status']


    else: # incus info (纯文本) 命令执行失败的情况
        incus_error_detail = text_data # text_data 变量此时包含 run_incus_command 返回的错误信息
        simulated_json_output['message'] = f"获取容器 {name} 实时信息失败 (命令执行失败: {incus_error_detail}). 数据主要来自数据库快照。"
        # live_data_available 保持 False
        # 解析字段保持初始的数据库值或 N/A

    # 返回模拟的 JSON 结构
    # 如果数据库信息不存在，前面已经返回404了，这里肯定是db_info存在的
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
        # 检查 containers 表是否存在
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='containers';")
        if not cursor.fetchone():
            print(f"错误：数据库表 'containers' 在 '{DATABASE_NAME}' 中未找到。")
            print("请确保 'python init_db.py' 已成功运行并创建了表结构。")
            # 建议删除旧文件并重新运行init_db.py
            print("您可以尝试删除旧的 incus_manager.db 文件然后重新运行 init_db.py。")
            return

        # 检查 containers 表是否有必需的列 (至少 incus_name, status, created_at, image_source)
        cursor.execute("PRAGMA table_info(containers);")
        columns = [col[1] for col in cursor.fetchall()]
        required_columns = ['incus_name', 'status', 'created_at', 'image_source']
        missing_columns = [col for col in required_columns if col not in columns]
        if missing_columns:
            print(f"错误：数据库表 'containers' 缺少必需的列: {', '.join(missing_columns)}")
            print("请确保 'python init_db.py' 已成功运行并创建了正确的表结构。")
            print("您可以尝试删除旧的 incus_manager.db 文件然后重新运行 init_db.py。")
            return


    except sqlite3.Error as e:
        print(f"启动时数据库检查错误: {e}")
        return
    finally:
        if conn:
            conn.close()

    # 确保Inc us命令存在且可执行 (基本检查)
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
