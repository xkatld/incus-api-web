# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for
import subprocess # 用于执行命令行
import json       # 用于解析 incus 的 JSON 输出
import sqlite3
import datetime
import os # 引入 os 模块
import time # 引入 time 模块

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
    cur.execute(query, args)
    rv = cur.fetchall()
    conn.commit()
    conn.close()
    return (rv[0] if rv else None) if one else rv

# --- Incus 命令行辅助函数 ---
def run_incus_command(command_parts, parse_json=True):
    """
    执行 Incus 命令并返回结果。
    """
    try:
        result = subprocess.run(command_parts, capture_output=True, text=True, check=False, timeout=30)
        
        if result.returncode != 0:
            error_message = result.stderr.strip() if result.stderr else result.stdout.strip()
            app.logger.error(f"Incus command failed: {' '.join(command_parts)}\nError: {error_message}")
            return False, f"命令执行失败: {error_message}"

        if parse_json:
            try:
                return True, json.loads(result.stdout)
            except json.JSONDecodeError:
                app.logger.error(f"Failed to parse JSON from incus: {result.stdout}")
                if result.stdout.strip():
                    return True, result.stdout.strip() 
                return False, "解析 Incus 输出为 JSON 失败"
        else:
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
            # 尝试解析，如果失败则用当前时间字符串
            # Incus V5.21+ created_at is a string like "2024-02-21T08:08:10.123456789Z"
            # Python's fromisoformat before 3.11 doesn't like more than 6 decimal places for microseconds
            # and doesn't always handle Z well without timezone awareness.
            if 'Z' in created_at_to_db:
                created_at_to_db = created_at_to_db.replace("Z", "+00:00")
            
            # Truncate microseconds if too long
            parts = created_at_to_db.split('.')
            if len(parts) > 1:
                second_part = parts[1]
                tz_part = ""
                if '+' in second_part:
                    idx = second_part.find('+')
                    tz_part = second_part[idx:]
                    second_part = second_part[:idx]
                elif '-' in second_part and len(second_part.split('-')[-1]) == 4 : # check for -HHMM timezone
                    idx = second_part.rfind('-') # find last - for timezone
                    if idx > 6 : # ensure it's not part of date like YYYY-MM-DD
                        tz_part = second_part[idx:]
                        second_part = second_part[:idx]

                if len(second_part) > 6:
                    second_part = second_part[:6]
                created_at_to_db = parts[0] + '.' + second_part + tz_part


            datetime.datetime.fromisoformat(created_at_to_db)
        except (ValueError, AttributeError) as ve: # AttributeError if created_at_to_db is None
            app.logger.warning(f"无法解析创建时间 '{created_at_str}' for {name}, 使用当前时间. Error: {ve}")
            created_at_to_db = datetime.datetime.now().isoformat()

        cursor.execute('''
            INSERT INTO containers (incus_name, image_source, status, created_at, last_synced)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(incus_name) DO UPDATE SET
                image_source = excluded.image_source,
                status = excluded.status,
                created_at = excluded.created_at,
                last_synced = CURRENT_TIMESTAMP
        ''', (name, image_source, status, created_at_to_db))
        conn.commit()
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 sync_container_to_db for {name}: {e}")
    finally:
        if conn:
            conn.close()

def remove_container_from_db(name):
    """从数据库中移除容器信息"""
    query_db('DELETE FROM containers WHERE incus_name = ?', [name])


# --- Flask 路由 ---

@app.route('/')
def index():
    """主页面，列出容器"""
    success, containers_data = run_incus_command(['incus', 'list', '--format', 'json'])
    
    listed_containers = []
    db_containers_dict = {}
    try:
        db_containers_dict = {row['incus_name']: dict(row) for row in query_db('SELECT * FROM containers')}
    except sqlite3.OperationalError as e:
        app.logger.error(f"数据库表 'containers' 可能不存在: {e}. 请运行 init_db.py.")
        # flash("数据库错误：容器表未找到，请运行 init_db.py。", "danger") # 需要 import flash

    incus_error_message = None
    if not success:
        incus_error_message = containers_data 

    if success and isinstance(containers_data, list):
        for item in containers_data:
            if not isinstance(item, dict) or 'name' not in item: # 确保 item 是字典且有 name
                app.logger.warning(f"Skipping invalid item in containers_data: {item}")
                continue

            item_name = item['name'] # 安全获取 name

            # 获取 image_source
            image_source = 'N/A'
            item_config = item.get('config')
            if isinstance(item_config, dict):
                image_source = item_config.get('image.description', 'N/A')
                if not image_source or image_source == 'N/A':
                     image_source = item_config.get('volatile.cloud-init.instance-id', 'N/A')
            
            # 获取 created_at
            created_at_str = item.get('created_at', datetime.datetime.now().isoformat())

            # --- 更安全地获取 IP 地址 (再次重构) ---
            ip_address = 'N/A'
            container_state = item.get('state') # item 已经是 dict 了

            if isinstance(container_state, dict):
                network_info = container_state.get('network') # network_info 可能是 None
                if isinstance(network_info, dict):
                    # 遍历所有网络接口，查找eth0或其他常见接口
                    for iface_name, iface_data in network_info.items(): # iface_data 可能是 None
                        if (iface_name.startswith('eth') or \
                            iface_name.startswith('enp') or \
                            iface_name.startswith('ens')) and \
                           isinstance(iface_data, dict): # 确保 iface_data 是字典

                            addresses = iface_data.get('addresses') # addresses 可能是 None
                            if isinstance(addresses, list) and addresses: # 确保是列表且不为空
                                found_global_ip = False
                                for addr_entry in addresses: # addr_entry 可能是 None
                                    if isinstance(addr_entry, dict): # 确保 addr_entry 是字典
                                        addr = addr_entry.get('address')
                                        family = addr_entry.get('family')
                                        scope = addr_entry.get('scope')
                                        if addr and family == 'inet' and scope == 'global':
                                            ip_address = addr
                                            found_global_ip = True
                                            break # 找到一个全局 IPv4 即可
                                if found_global_ip:
                                    break # 已经为该容器找到 IP，跳出接口循环
                                
                                # 如果没找到全局 IPv4, 尝试找任何全局 IP (如 IPv6)
                                if not found_global_ip:
                                    for addr_entry in addresses:
                                        if isinstance(addr_entry, dict):
                                            addr = addr_entry.get('address')
                                            scope = addr_entry.get('scope')
                                            if addr and scope == 'global':
                                                ip_address = addr
                                                found_global_ip = True
                                                break
                                    if found_global_ip:
                                        break 
            # --- IP 地址获取结束 ---

            container_info = {
                'name': item_name,
                'status': item.get('status', 'Unknown'), # item 已经是 dict
                'image_source': image_source,
                'ip': ip_address,
                'created_at': created_at_str,
            }
            listed_containers.append(container_info)
            sync_container_to_db(item_name, image_source, item.get('status', 'Unknown'), created_at_str)
        
        incus_container_names = {c['name'] for c in listed_containers}
        for db_name in list(db_containers_dict.keys()):
            if db_name not in incus_container_names:
                remove_container_from_db(db_name)
                app.logger.info(f"从数据库中移除了不存在的容器: {db_name}")
    
    elif not success and db_containers_dict: # Incus 失败，但DB有数据
        app.logger.warning(f"无法从 Incus 获取容器列表 ({incus_error_message})，尝试从数据库加载。")
        for name, data in db_containers_dict.items():
            listed_containers.append({
                'name': name,
                'status': data.get('status', 'Unknown'),
                'image_source': data.get('image_source', 'N/A (from DB)'),
                'ip': 'N/A (from DB)',
                'created_at': data.get('created_at', 'N/A (from DB)')
            })
    
    success_img, images_data = run_incus_command(['incus', 'image', 'list', '--format', 'json'])
    available_images = []
    if success_img and isinstance(images_data, list):
        for img in images_data:
            if not isinstance(img, dict): continue

            alias_name = None
            aliases = img.get('aliases')
            if isinstance(aliases, list) and aliases:
                alias_name_entry = aliases[0]
                if isinstance(alias_name_entry, dict):
                    alias_name = alias_name_entry.get('name')
            
            if not alias_name:
                fingerprint = img.get('fingerprint')
                alias_name = fingerprint[:12] if isinstance(fingerprint, str) else 'unknown_image'
            
            description_props = img.get('properties')
            description = 'N/A'
            if isinstance(description_props, dict):
                description = description_props.get('description', 'N/A')

            available_images.append({'name': alias_name, 'description': f"{alias_name} ({description})"})
    else:
        error_msg_img = images_data if not success_img else 'Invalid image data format'
        app.logger.error(f"获取镜像列表失败: {error_msg_img}")


    return render_template('index.html', 
                           containers=listed_containers, 
                           images=available_images, 
                           incus_error=(not success, incus_error_message))

@app.route('/container/create', methods=['POST'])
def create_container():
    name = request.form.get('name')
    image = request.form.get('image')
    if not name or not image:
        return jsonify({'status': 'error', 'message': '容器名称和镜像不能为空'}), 400

    success, output = run_incus_command(['incus', 'launch', image, name], parse_json=False)
    if success:
        time.sleep(2) # 给容器一点时间启动
        
        _, info = run_incus_command(['incus', 'info', name, '--format', 'json'])
        created_at = datetime.datetime.now().isoformat()
        image_source_desc = image
        status_val = 'Running' # 默认为 Running

        if info and isinstance(info, dict):
            created_at = info.get('created_at', created_at)
            config_info = info.get('config')
            if isinstance(config_info, dict):
                image_source_desc = config_info.get('image.description', image)
            status_val = info.get('status', status_val)
        
        sync_container_to_db(name, image_source_desc, status_val, created_at)
            
        return jsonify({'status': 'success', 'message': f'容器 {name} 创建并启动成功: {output}'})
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

    success, output = run_incus_command(commands[action], parse_json=False)
    
    if success:
        message = f'容器 {name} {action} 操作提交成功。'
        if action == 'delete':
            remove_container_from_db(name)
            message = f'容器 {name} 已删除。'
        else:
            time.sleep(1) # 给操作一点时间生效
            _, list_output = run_incus_command(['incus', 'list', name, '--format', 'json'])
            
            db_image_source = 'N/A'
            db_created_at = datetime.datetime.now().isoformat()
            new_status_val = 'Unknown'

            old_db_entry = query_db('SELECT image_source, created_at, status FROM containers WHERE incus_name = ?', [name], one=True)
            if old_db_entry:
                db_image_source = old_db_entry['image_source']
                db_created_at = old_db_entry['created_at']
                new_status_val = old_db_entry['status'] # 默认使用旧状态

            if list_output and isinstance(list_output, list) and len(list_output) > 0:
                container_data = list_output[0]
                if isinstance(container_data, dict):
                    new_status_val = container_data.get('status', new_status_val)
                    cfg = container_data.get('config')
                    if isinstance(cfg, dict):
                        db_image_source = cfg.get('image.description', db_image_source)
                    db_created_at = container_data.get('created_at', db_created_at)
                    message = f'容器 {name} {action} 操作成功，新状态: {new_status_val}。'
            
            # 即使 list_output 失败，也根据动作乐观更新
            if action == 'start': new_status_val = 'Running'
            elif action == 'stop': new_status_val = 'Stopped'
            # restart 的状态在 list_output 中应该是 Running
            
            sync_container_to_db(name, db_image_source, new_status_val, db_created_at)

        return jsonify({'status': 'success', 'message': message})
    else:
        return jsonify({'status': 'error', 'message': f'容器 {name} {action} 操作失败: {output}'}), 500

@app.route('/container/<name>/exec', methods=['POST'])
def exec_command(name):
    command_to_exec = request.form.get('command')
    if not command_to_exec:
        return jsonify({'status': 'error', 'message': '执行的命令不能为空'}), 400

    command_parts = command_to_exec.split()
    success, output = run_incus_command(['incus', 'exec', name, '--'] + command_parts, parse_json=False)
    
    if success:
        return jsonify({'status': 'success', 'output': output})
    else:
        return jsonify({'status': 'error', 'output': output}), 500

@app.route('/container/<name>/info')
def container_info(name):
    """获取容器详细信息"""
    success, data = run_incus_command(['incus', 'info', name, '--format', 'json']) # 尝试用 JSON 格式

    if success and isinstance(data, dict): # 如果成功获取并解析了 JSON
        # 从 Incus 的 JSON 输出中提取关键信息并同步到数据库
        image_source = 'N/A'
        config_data = data.get('config')
        if isinstance(config_data, dict):
            image_source = config_data.get('image.description', 'N/A')
        
        created_at = data.get('created_at', datetime.datetime.now().isoformat())
        status = data.get('status', 'Unknown')
        sync_container_to_db(name, image_source, status, created_at)
        return jsonify(data) # 返回完整的 JSON 数据
    else:
        # JSON 获取失败 (可能是 --format 不支持，或者其他错误)
        # data 变量此时应该是 run_incus_command 返回的错误信息字符串
        incus_error_detail = data if not success else "Incus 返回了无效的数据格式或不支持 JSON 输出"
        app.logger.warning(f"无法从 Incus 获取容器 '{name}' 的 JSON info: {incus_error_detail}")

        # 尝试获取纯文本的 incus info (可选，如果需要显示一些基本信息)
        # success_text, text_data = run_incus_command(['incus', 'info', name], parse_json=False)
        # text_info_to_display = text_data if success_text else "无法获取文本格式的 Incus info。"

        # 主要依赖数据库快照
        db_info = query_db('SELECT * FROM containers WHERE incus_name = ?', [name], one=True)
        if db_info:
            response_data = {
                'name': db_info['incus_name'],
                'status': db_info['status'],
                'image_source': db_info['image_source'],
                'created_at': db_info['created_at'],
                'message': f"数据来自数据库快照。无法从 Incus 获取详细实时配置信息 (原因: {incus_error_detail}).",
                # 'raw_text_info': text_info_to_display # 如果选择包含文本信息
            }
            # 如果JSON获取失败，但我们至少有数据库信息，我们就不再尝试同步数据库了，
            # 因为我们没有从incus得到新的准确信息来同步。
            return jsonify(response_data)
        else:
            # 连数据库信息都没有
            return jsonify({
                'status': 'error',
                'message': f"获取容器 {name} 信息失败: 无法从 Incus 获取 ({incus_error_detail}) 且数据库中无记录。"
            }), 404


def main():
    if not os.path.exists(DATABASE_NAME):
        print(f"错误：数据库文件 '{DATABASE_NAME}' 未找到。")
        print("请先运行 'python init_db.py' 来初始化数据库。")
        return

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='containers';")
        if not cursor.fetchone():
            print(f"错误：数据库表 'containers' 在 '{DATABASE_NAME}' 中未找到。")
            print("请确保 'python init_db.py' 已成功运行并创建了表结构。")
            print("你可以尝试删除旧的 incus_manager.db 文件然后重新运行 init_db.py。")
            return
    except sqlite3.Error as e:
        print(f"启动时数据库检查错误: {e}")
        return
    finally:
        if conn:
            conn.close()

    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()
