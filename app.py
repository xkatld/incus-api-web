# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for
import subprocess # 用于执行命令行
import json       # 用于解析 incus 的 JSON 输出
import sqlite3
import datetime

app = Flask(__name__)
DATABASE_NAME = 'incus_manager.db'

# --- 数据库辅助函数 ---
def get_db_connection():
    """获取数据库连接"""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row # 让查询结果可以像字典一样访问列
    return conn

def query_db(query, args=(), one=False):
    """执行数据库查询"""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    conn.commit() # 确保写入操作被提交
    conn.close()
    return (rv[0] if rv else None) if one else rv

# --- Incus 命令行辅助函数 ---
def run_incus_command(command_parts, parse_json=True):
    """
    执行 Incus 命令并返回结果。
    :param command_parts: 命令及其参数的列表，例如 ['incus', 'list', '--format', 'json']
    :param parse_json: 是否尝试将输出解析为 JSON
    :return: (成功标志, 输出或错误信息)
    """
    try:
        # 注意: 实际生产环境中需要更严格的权限控制和输入验证
        # 如果 incus 命令需要 sudo，请在命令前添加 'sudo'
        # 例如: result = subprocess.run(['sudo'] + command_parts, ...)
        result = subprocess.run(command_parts, capture_output=True, text=True, check=False)
        
        if result.returncode != 0:
            # 命令执行失败，返回错误信息
            error_message = result.stderr.strip() if result.stderr else result.stdout.strip()
            app.logger.error(f"Incus command failed: {' '.join(command_parts)}\nError: {error_message}")
            return False, f"命令执行失败: {error_message}"

        if parse_json:
            try:
                return True, json.loads(result.stdout)
            except json.JSONDecodeError:
                app.logger.error(f"Failed to parse JSON from incus: {result.stdout}")
                return False, "解析 Incus 输出为 JSON 失败"
        else:
            return True, result.stdout.strip() # 返回原始文本输出
    except FileNotFoundError:
        app.logger.error("Incus command not found. Is Incus installed and in PATH?")
        return False, "Incus 命令未找到。请确保 Incus 已安装并在系统 PATH 中。"
    except Exception as e:
        app.logger.error(f"Exception running incus command: {e}")
        return False, f"执行 Incus 命令时发生异常: {str(e)}"

def sync_container_to_db(name, image_source, status, created_at_str):
    """将容器信息同步或添加到数据库"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO containers (incus_name, image_source, status, created_at, last_synced)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(incus_name) DO UPDATE SET
                image_source = excluded.image_source,
                status = excluded.status,
                created_at = excluded.created_at,
                last_synced = CURRENT_TIMESTAMP
        ''', (name, image_source, status, created_at_str))
        conn.commit()
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 sync_container_to_db for {name}: {e}")
    finally:
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
    db_containers_dict = {row['incus_name']: dict(row) for row in query_db('SELECT * FROM containers')}
    
    if success:
        for item in containers_data:
            # 从 Incus 获取更详细的创建时间等信息 (如果需要)
            # 这里简化处理，主要依赖 Incus list 的信息，并通过 sync_container_to_db 更新数据库
            # image_source 需要从 config 中获取，或通过 incus info 获取
            image_source = item.get('config', {}).get('image.description', 'N/A')
            if not image_source or image_source == 'N/A': # 尝试其他可能的字段
                image_source = item.get('config', {}).get('volatile.cloud-init.instance-id', 'N/A') # 有时候 image 信息在这里
            
            created_at_str = item.get('created_at', datetime.datetime.now().isoformat()) # 获取创建时间

            container_info = {
                'name': item['name'],
                'status': item['status'],
                'image_source': image_source,
                'ip': item.get('state', {}).get('network', {}).get('eth0', {}).get('addresses', [{}])[0].get('address', 'N/A') if item.get('state') else 'N/A',
                'created_at': created_at_str, # 使用 incus list 里的创建时间
            }
            listed_containers.append(container_info)
            # 同步到数据库
            sync_container_to_db(item['name'], image_source, item['status'], created_at_str)
        
        # 检查数据库中是否存在但 Incus list 中已不存在的容器，并从数据库中移除
        incus_container_names = {c['name'] for c in listed_containers}
        for db_name in list(db_containers_dict.keys()): # 使用 list 复制 keys，因为我们可能修改 dict
            if db_name not in incus_container_names:
                remove_container_from_db(db_name)
                app.logger.info(f"从数据库中移除了不存在的容器: {db_name}")
    else:
        # 如果 Incus 命令失败，尝试从数据库加载数据显示，并提示错误
        app.logger.warning("无法从 Incus 获取容器列表，尝试从数据库加载。")
        db_data = query_db('SELECT incus_name as name, status, image_source, created_at FROM containers')
        listed_containers = [dict(row) for row in db_data]
        # 可以添加一个 flash 消息提示用户 Incus 连接问题
        # from flask import flash
        # flash(f"无法连接到 Incus: {containers_data}", "error") # containers_data此时是错误信息
    
    # 获取可用镜像列表
    success_img, images_data = run_incus_command(['incus', 'image', 'list', '--format', 'json'])
    available_images = []
    if success_img:
        for img in images_data:
            # 通常用 aliases[0]['name'] 或 properties['description']
            # 这里简化，优先用 fingerprint 如果没有 alias
            alias_name = img.get('aliases', [{}])[0].get('name') if img.get('aliases') else img.get('fingerprint')[:12]
            description = img.get('properties', {}).get('description', 'N/A')
            available_images.append({'name': alias_name, 'description': f"{alias_name} ({description})"})
    else:
        app.logger.error(f"获取镜像列表失败: {images_data}")


    return render_template('index.html', containers=listed_containers, images=available_images, incus_error=(not success, containers_data))

@app.route('/container/create', methods=['POST'])
def create_container():
    """创建容器"""
    name = request.form.get('name')
    image = request.form.get('image')
    if not name or not image:
        return jsonify({'status': 'error', 'message': '容器名称和镜像不能为空'}), 400

    # 注意：实际生产中，不要直接将用户输入拼接到命令中，这里 image 来自选择，相对安全
    success, output = run_incus_command(['incus', 'launch', image, name], parse_json=False)
    if success:
        # 创建成功后，获取信息并存入数据库
        _, info = run_incus_command(['incus', 'info', name, '--format', 'json'])
        if info and isinstance(info, dict): # 确保 info 是字典
            created_at = info.get('created_at', datetime.datetime.now().isoformat())
            image_source_desc = info.get('config', {}).get('image.description', image) # Fallback to selected image
            sync_container_to_db(name, image_source_desc, 'Running', created_at) # launch后通常是Running
        return jsonify({'status': 'success', 'message': f'容器 {name} 创建并启动成功: {output}'})
    else:
        return jsonify({'status': 'error', 'message': f'创建容器 {name} 失败: {output}'}), 500

@app.route('/container/<name>/action', methods=['POST'])
def container_action(name):
    """对容器执行操作：启动/停止/重启/删除"""
    action = request.form.get('action')
    commands = {
        'start': ['incus', 'start', name],
        'stop': ['incus', 'stop', name, '--force'], # 添加 --force 避免等待
        'restart': ['incus', 'restart', name, '--force'],
        'delete': ['incus', 'delete', name, '--force'],
    }
    if action not in commands:
        return jsonify({'status': 'error', 'message': '无效的操作'}), 400

    success, output = run_incus_command(commands[action], parse_json=False)
    
    if success:
        if action == 'delete':
            remove_container_from_db(name)
            message = f'容器 {name} 已删除'
        else:
            # 操作成功后，更新数据库中的状态
            _, current_status_info = run_incus_command(['incus', 'list', name, '--format', 'json'])
            new_status = 'Unknown'
            if current_status_info and len(current_status_info) > 0:
                new_status = current_status_info[0].get('status', 'Unknown')
                image_source = current_status_info[0].get('config', {}).get('image.description', 'N/A')
                created_at = current_status_info[0].get('created_at', datetime.datetime.now().isoformat())
                sync_container_to_db(name, image_source, new_status, created_at) # 更新状态
            message = f'容器 {name} {action} 操作成功'
        return jsonify({'status': 'success', 'message': message})
    else:
        return jsonify({'status': 'error', 'message': f'容器 {name} {action} 操作失败: {output}'}), 500

@app.route('/container/<name>/exec', methods=['POST'])
def exec_command(name):
    """在容器内执行命令"""
    command_to_exec = request.form.get('command')
    if not command_to_exec:
        return jsonify({'status': 'error', 'message': '执行的命令不能为空'}), 400

    # 注意: '--' 用于分隔 incus exec 的参数和要在容器内执行的命令
    # 将命令字符串按空格分割成列表
    command_parts = command_to_exec.split()
    success, output = run_incus_command(['incus', 'exec', name, '--'] + command_parts, parse_json=False)
    
    if success:
        return jsonify({'status': 'success', 'output': output})
    else:
        # output 此时是错误信息
        return jsonify({'status': 'error', 'output': output}), 500

@app.route('/container/<name>/info')
def container_info(name):
    """获取容器详细信息"""
    success, data = run_incus_command(['incus', 'info', name, '--format', 'json'])
    if success:
        # 将获取到的信息同步/更新到数据库
        image_source = data.get('config', {}).get('image.description', 'N/A')
        created_at = data.get('created_at', datetime.datetime.now().isoformat())
        status = data.get('status', 'Unknown')
        sync_container_to_db(name, image_source, status, created_at)
        return jsonify(data)
    else:
        # 如果 Incus 查询失败，尝试从数据库获取
        db_info = query_db('SELECT * FROM containers WHERE incus_name = ?', [name], one=True)
        if db_info:
            return jsonify({
                'name': db_info['incus_name'],
                'status': db_info['status'],
                'image_source': db_info['image_source'],
                'created_at': db_info['created_at'],
                'message': '数据来自数据库快照，可能不是最新的。无法从 Incus 获取实时信息。',
                'error_details': data # data 此时是错误信息
            })
        return jsonify({'status': 'error', 'message': f'获取容器 {name} 信息失败: {data}'}), 404


if __name__ == '__main__':
    # 确保数据库已初始化
    # init_db.create_tables() # 已经在 init_db.py 中独立运行了
    app.run(debug=True, host='0.0.0.0', port=5000) # 允许局域网访问
