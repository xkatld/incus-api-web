from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort
import subprocess
import json
import sqlite3
import datetime
import os
import time
import re
import shlex
import sys
import secrets
import hashlib
from functools import wraps

app = Flask(__name__)

app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(16))

DATABASE_NAME = 'incus_manager.db'

SETTINGS = {}

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

def load_settings_from_db():
    global SETTINGS
    try:
        settings_rows = query_db('SELECT key, value FROM settings')
        if not settings_rows:
            app.logger.error("从数据库加载设置失败: 'settings' 表为空或不存在。请运行 init_db.py。")
            SETTINGS = {}
            return False
        SETTINGS = {row['key']: row['value'] for row in settings_rows}
        required_keys = ['admin_username', 'admin_password_hash', 'api_key_hash']
        for key in required_keys:
            if key not in SETTINGS:
                app.logger.error(f"从数据库加载设置失败: 缺少键 '{key}'。请运行 init_db.py 检查设置。")
                SETTINGS = {}
                return False
        app.logger.info("从数据库成功加载设置。")
        return True
    except sqlite3.OperationalError:
        app.logger.error("从数据库加载设置失败: 'settings' 表不存在。请运行 init_db.py。")
        SETTINGS = {}
        return False
    except Exception as e:
        app.logger.error(f"加载设置时发生异常: {e}")
        SETTINGS = {}
        return False


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('logged_in') is not True:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def verify_api_key_hash():
    api_key_hash_header = request.headers.get('X-API-Key-Hash')
    stored_api_key_hash = SETTINGS.get('api_key_hash')

    if not api_key_hash_header:
        app.logger.warning(f"API认证失败: 缺少 'X-API-Key-Hash' 请求头 from {request.remote_addr}")
        return False

    if not stored_api_key_hash:
        app.logger.error("API认证失败: 未从数据库加载到 'api_key_hash'。请检查设置。")
        return False

    if api_key_hash_header == stored_api_key_hash:
        app.logger.debug(f"API密钥哈希认证成功 from {request.remote_addr}")
        return True
    else:
        app.logger.warning(f"API密钥哈希认证失败: 哈希值不匹配 from {request.remote_addr}")
        return False

def web_or_api_authentication_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not SETTINGS:
             app.logger.error("认证失败: 设置未加载。请检查数据库和 init_db.py 运行情况。")
             if request.method == 'GET':
                 return render_template('index.html', incus_error=(True, "应用设置未加载。请检查数据库和 init_db.py 运行情况。"), containers=[], images=[]), 500
             else:
                 return jsonify({'status': 'error', 'message': '认证失败: 应用设置未加载。'}), 500

        is_authenticated_via_session = session.get('logged_in') is True
        is_authenticated_via_api = verify_api_key_hash()

        if is_authenticated_via_session or is_authenticated_via_api:
            return f(*args, **kwargs)
        else:
            if request.method == 'GET':
                return redirect(url_for('login', next=request.url))
            else:
                return jsonify({'status': 'error', 'message': '需要认证'}), 401
    return decorated_function


def run_command(command_parts, parse_json=True, timeout=60):
    try:
        env_vars = os.environ.copy()
        env_vars['LC_ALL'] = 'C.UTF-8'
        env_vars['LANG'] = 'C.UTF-8'

        log_command = ' '.join(shlex.quote(part) for part in command_parts)
        app.logger.info(f"执行命令: {log_command}")

        result = subprocess.run(command_parts, capture_output=True, text=True, check=False, timeout=timeout, env=env_vars)

        if result.returncode != 0:
            error_message = result.stderr.strip() if result.stderr else result.stdout.strip()
            app.logger.error(f"命令失败 (退出码 {result.returncode}): {log_command}\n错误: {error_message}")
            return False, error_message
        else:
             if parse_json:
                 try:
                    output_text = result.stdout.strip()
                    if output_text.startswith(u'\ufeff'):
                        output_text = output_text[1:]
                    return True, json.loads(output_text)
                 except json.JSONDecodeError as e:
                    app.logger.error(f"无法解析命令输出为 JSON: {result.stdout}\n错误: {e}")
                    return False, f"解析命令输出为 JSON 失败: {e}\n原始输出: {result.stdout.strip()}"
             else:
                 return True, result.stdout.strip()

    except FileNotFoundError:
        command_name = command_parts[0] if command_parts else 'command'
        app.logger.error(f"命令未找到: {command_name}")
        return False, f"命令 '{command_name}' 未找到。请确保它已安装并在系统 PATH 中。"
    except subprocess.TimeoutExpired:
        app.logger.error(f"命令超时 (>{timeout}s): {log_command}")
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
                           if '.' not in created_at_to_db:
                              created_at_to_db = created_at_to_db.replace(tz_part, '.000000' + tz_part)


                datetime.datetime.fromisoformat(created_at_to_db)

            except (ValueError, AttributeError, TypeError) as ve:
                app.logger.warning(f"无法精确解析 Incus 创建时间 '{original_created_at_to_db}' for {name} 为 ISO 格式 ({ve}). 将尝试使用数据库记录的原值或当前时间.")
                old_db_entry = query_db('SELECT created_at FROM containers WHERE incus_name = ?', [name], one=True)
                if old_db_entry and old_db_entry['created_at']:
                     try:
                          datetime.datetime.fromisoformat(old_db_entry['created_at'])
                          created_at_to_db = old_db_entry['created_at']
                          app.logger.info(f"使用数据库记录的创建时间 '{created_at_to_db}' for {name}.")
                     except (ValueError, TypeError):
                          app.logger.warning(f"数据库记录的创建时间 '{old_db_entry['created_at']}' for {name} 也是无效 ISO 格式.")
                          created_at_to_db = datetime.datetime.now().isoformat()
                          app.logger.info(f"使用当前时间作为创建时间 for {name}.")
                else:
                     created_at_to_db = datetime.datetime.now().isoformat()
                     app.logger.info(f"使用当前时间作为创建时间 for {name} (Incus did not provide created_at).")

        else:
             old_db_entry = query_db('SELECT created_at FROM containers WHERE incus_name = ?', [name], one=True)
             if old_db_entry and old_db_entry['created_at']:
                 try:
                      datetime.datetime.fromisoformat(old_db_entry['created_at'])
                      created_at_to_db = old_db_entry['created_at']
                      app.logger.info(f"使用数据库记录的创建时间 '{created_at_to_db}' for {name} (Incus did not provide created_at).")
                 except (ValueError, TypeError):
                      app.logger.warning(f"数据库记录的创建时间 '{old_db_entry['created_at']}' for {name} 也是无效 ISO 格式 (Incus did not provide created_at).")
                      created_at_to_db = datetime.datetime.now().isoformat()
                      app.logger.info(f"使用当前时间作为创建时间 for {name} (Incus did not provide created_at).")
             else:
                  created_at_to_db = datetime.datetime.now().isoformat()
                  app.logger.info(f"使用当前时间作为创建时间 for {name} (Incus did not provide created_at).")


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
        query_db('DELETE FROM nat_rules WHERE container_name = ?', [name])
        query_db('DELETE FROM containers WHERE incus_name = ?', [name])
        app.logger.info(f"从数据库中移除了容器及其NAT规则记录: {name}")
    except sqlite3.Error as e:
         app.logger.error(f"数据库错误 remove_container_from_db for {name}: {e}")


def _get_container_raw_info(name):
    db_info = query_db('SELECT * FROM containers WHERE incus_name = ?', [name], one=True)
    success_live, live_data = run_incus_command(['list', name, '--format', 'json'])

    if success_live and isinstance(live_data, list) and len(live_data) > 0 and isinstance(live_data[0], dict):
        container_data = live_data[0]
        info_output = {
            'name': container_data.get('name', name),
            'status': container_data.get('status', '未知'),
            'status_code': container_data.get('status_code', 0),
            'type': container_data.get('type', '未知'),
            'architecture': container_data.get('architecture', 'N/A'),
            'ephemeral': container_data.get('ephemeral', False),
            'created_at': container_data.get('created_at', None),
            'profiles': container_data.get('profiles', []),
            'config': container_data.get('config', {}),
            'devices': container_data.get('devices', {}),
            'snapshots': container_data.get('snapshots', []),
             'state': container_data.get('state', {}),
            'description': container_data.get('config', {}).get('image.description', 'N/A'),
            'ip': 'N/A',
            'live_data_available': True,
            'message': '数据主要来自 Incus 实时信息。',
        }

        container_state = info_output.get('state')
        if isinstance(container_state, dict):
            network_info = container_state.get('network')
            if isinstance(network_info, dict):
                for iface_name, iface_data in network_info.items():
                    if isinstance(iface_data, dict):
                        addresses = iface_data.get('addresses')
                        if isinstance(addresses, list):
                            for addr_entry in addresses:
                                if isinstance(addr_entry, dict):
                                    addr = addr_entry.get('address')
                                    family = addr_entry.get('family')
                                    scope = addr_entry.get('scope')
                                    if addr and family == 'inet' and scope == 'global':
                                        info_output['ip'] = addr.split('/')[0]
                                        break
                            if info_output['ip'] != 'N/A': break

        return info_output, None

    elif db_info:
        info_output = {
            'name': db_info['incus_name'],
            'status': db_info.get('status', '未知'),
            'status_code': 0,
            'type': '容器',
            'architecture': db_info.get('architecture', 'N/A'),
            'ephemeral': False,
            'created_at': db_info.get('created_at', None),
            'profiles': [],
            'config': {},
            'devices': {},
            'snapshots': [],
             'state': {'status': db_info.get('status', '未知'), 'status_code': 0, 'network': {}},
            'description': db_info.get('image_source', 'N/A'),
            'ip': 'N/A',
            'live_data_available': False,
            'message': '无法从 Incus 获取实时信息，数据主要来自数据库快照。',
        }
        return info_output, info_output['message']

    else:
        error_message = f"获取容器 {name} 信息失败: 数据库中无记录且无法从 Incus 获取实时信息。"
        return None, error_message

def check_nat_rule_exists_in_db(container_name, host_port, protocol):
    try:
        rule = query_db('''
            SELECT id FROM nat_rules
            WHERE container_name = ? AND host_port = ? AND protocol = ?
        ''', (container_name, host_port, protocol), one=True)
        return True, rule is not None
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 check_nat_rule_exists_in_db for {container_name}, host={host_port}/{protocol}: {e}")
        return False, f"检查规则记录失败: {e}"

def add_nat_rule_to_db(rule_details):
    try:
        query_db('''
            INSERT INTO nat_rules (container_name, host_port, container_port, protocol, ip_at_creation)
            VALUES (?, ?, ?, ?, ?)
        ''', (rule_details['container_name'], rule_details['host_port'],
              rule_details['container_port'], rule_details['protocol'],
              rule_details['ip_at_creation']))
        inserted_row = query_db('SELECT last_insert_rowid()', one=True)
        rule_id = inserted_row[0] if inserted_row else None
        app.logger.info(f"Added NAT rule to DB: ID {rule_id}, {rule_details['container_name']}, host={rule_details['host_port']}/{rule_details['protocol']}, container={rule_details['ip_at_creation']}:{rule_details['container_port']}")
        return True, rule_id
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 add_nat_rule_to_db for {rule_details.get('container_name', 'N/A')}: {e}")
        return False, f"添加规则记录到数据库失败: {e}"

def get_nat_rules_for_container(container_name):
    try:
        rules = query_db('SELECT id, host_port, container_port, protocol, ip_at_creation, created_at FROM nat_rules WHERE container_name = ?', [container_name])
        return True, [dict(row) for row in rules]
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 get_nat_rules_for_container for {container_name}: {e}")
        return False, f"从数据库获取规则失败: {e}"

def get_nat_rule_by_id(rule_id):
    try:
        rule = query_db('SELECT id, container_name, host_port, container_port, protocol, ip_at_creation FROM nat_rules WHERE id = ?', [rule_id], one=True)
        return True, dict(rule) if rule else None
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 get_nat_rule_by_id for id {rule_id}: {e}")
        return False, f"从数据库获取规则 (ID {rule_id}) 失败: {e}"

def remove_nat_rule_from_db(rule_id):
    try:
        query_db('DELETE FROM nat_rules WHERE id = ?', [rule_id])
        app.logger.info(f"Removed NAT rule record from DB: ID {rule_id}")
        return True, "规则记录成功从数据库移除。"
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 remove_nat_rule_from_db for id {rule_id}: {e}")
        return False, f"从数据库移除规则记录失败: {e}"

def perform_iptables_delete_for_rule(rule_details):
    if not isinstance(rule_details, dict):
        return False, "Invalid rule details provided for iptables deletion.", False

    required_keys = ['host_port', 'container_port', 'protocol', 'ip_at_creation']
    if not all(key in rule_details for key in required_keys):
        return False, f"Missing required keys in rule details for iptables deletion. Requires: {required_keys}", False

    try:
        host_port = rule_details['host_port']
        container_port = rule_details['container_port']
        protocol = rule_details['protocol']
        ip_at_creation = rule_details['ip_at_creation']

        iptables_command = [
            'iptables',
            '-t', 'nat',
            '-D', 'PREROUTING',
            '-p', protocol,
            '--dport', str(host_port),
            '-j', 'DNAT',
            '--to-destination', f'{ip_at_creation}:{container_port}'
        ]

        app.logger.info(f"Executing iptables delete for rule ID {rule_details.get('id', 'N/A')}: {' '.join(shlex.quote(part) for part in iptables_command)}")

        success, output = run_command(iptables_command, parse_json=False, timeout=10)

        if success:
             app.logger.info(f"iptables delete successful for rule ID {rule_details.get('id', 'N/A')}.")
             return True, f"成功从 iptables 移除规则 (主机端口 {host_port}/{protocol} 到容器端口 {container_port} @ {ip_at_creation}).", False
        else:
             is_bad_rule = "Bad rule" in output
             app.logger.error(f"iptables delete failed for rule ID {rule_details.get('id', 'N/A')}: {output}. Is Bad Rule: {is_bad_rule}")
             return False, f"从 iptables 移除规则失败 (主机端口 {host_port}/{protocol} 到容器端口 {container_port} @ {ip_at_creation}): {output}", is_bad_rule

    except Exception as e:
        app.logger.error(f"Exception during perform_iptables_delete_for_rule for rule ID {rule_details.get('id', 'N/A')}: {e}")
        return False, f"执行 iptables 删除命令时发生异常: {str(e)}", False

def cleanup_orphaned_nat_rules_in_db(existing_incus_container_names):
    try:
        db_rule_container_names_rows = query_db('SELECT DISTINCT container_name FROM nat_rules')
        db_rule_container_names = {row['container_name'] for row in db_rule_container_names_rows}

        orphaned_names = [
            name for name in db_rule_container_names
            if name not in existing_incus_container_names
        ]

        if orphaned_names:
            app.logger.warning(f"检测到数据库中存在孤立的NAT规则记录，对应的容器已不存在于Incus: {orphaned_names}")
            placeholders = ','.join('?' * len(orphaned_names))
            query = f'DELETE FROM nat_rules WHERE container_name IN ({placeholders})'
            query_db(query, orphaned_names)
            app.logger.info(f"已从数据库中移除 {len(orphaned_names)} 个孤立容器 ({len(db_rule_container_names) - len(orphaned_names)} 个现有容器) 的NAT规则记录。")
            container_placeholders = ','.join('?' * len(orphaned_names))
            container_query = f'DELETE FROM containers WHERE incus_name IN ({container_placeholders})'
            query_db(container_query, orphaned_names)
            app.logger.info(f"已从数据库中移除 {len(orphaned_names)} 个孤立容器的容器记录 (如果存在)。")

    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 cleanup_orphaned_nat_rules_in_db: {e}")
    except Exception as e:
        app.logger.error(f"清理孤立NAT规则时发生异常: {e}")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if not SETTINGS:
        return render_template('index.html', incus_error=(True, "应用设置未加载。请检查数据库和 init_db.py 运行情况。"), containers=[], images=[]), 500

    admin_username = SETTINGS.get('admin_username')
    admin_password_hash = SETTINGS.get('admin_password_hash')

    if not admin_username or not admin_password_hash:
        return render_template('index.html', incus_error=(True, "数据库中缺少管理员账号或密码哈希设置。请运行 init_db.py。"), containers=[], images=[]), 500

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == admin_username and hashlib.sha256(password.encode('utf-8')).hexdigest() == admin_password_hash:
            session['logged_in'] = True
            app.logger.info(f"用户 '{username}' 登录成功。")
            next_url = request.args.get('next')
            return redirect(next_url or url_for('index'))
        else:
            app.logger.warning(f"用户 '{username}' 登录失败。")
            return render_template('index.html', login_error="用户名或密码错误。", containers=[], images=[])
    return render_template('index.html', login_form=True, containers=[], images=[])

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    app.logger.info("用户已退出登录。")
    return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
    if not SETTINGS:
        return render_template('index.html', incus_error=(True, "应用设置未加载。请检查数据库和 init_db.py 运行情况。"), containers=[], images=[]), 500

    success_list, containers_data = run_incus_command(['list', '--format', 'json'])

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


    incus_container_names_set = set()

    if not success_list:
        incus_error = True
        incus_error_message = containers_data
        app.logger.warning(f"无法从 Incus 获取容器列表 ({incus_error_message})，尝试从数据库加载。")
        for name, data in db_containers_dict.items():
            listed_containers.append({
                'name': name,
                'status': data.get('status', '未知 (来自数据库)'),
                'image_source': data.get('image_source', 'N/A (来自数据库)'),
                'ip': 'N/A (数据库信息)',
                'created_at': data.get('created_at', 'N/A (来自数据库)')
            })

    elif isinstance(containers_data, list):
        for item in containers_data:
            if not isinstance(item, dict) or 'name' not in item:
                app.logger.warning(f"Skipping invalid item in containers_data from Incus: {item}")
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
                         image_source = f"别名: {image_alias}"
                     else:
                         image_fingerprint = item_config.get('image.fingerprint')
                         if image_fingerprint and isinstance(image_fingerprint, str):
                              image_source = f"指纹: {image_fingerprint[:12]}"
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
                'status': item.get('status', '未知'),
                'image_source': image_source,
                'ip': ip_address,
                'created_at': created_at_str,
            }
            listed_containers.append(container_info)
            sync_container_to_db(item_name, image_source, item.get('status', '未知'), created_at_str)

        current_db_names = {row['incus_name'] for row in query_db('SELECT incus_name FROM containers')}
        vanished_names_from_db = [db_name for db_name in current_db_names if db_name not in incus_container_names_set]
        for db_name in vanished_names_from_db:
             remove_container_from_db(db_name)
             app.logger.info(f"根据 Incus 列表移除数据库中不存在的容器和NAT规则记录: {db_name}")

        cleanup_orphaned_nat_rules_in_db(incus_container_names_set)


    else:
        incus_error = True
        incus_error_message = f"Incus list 返回了未知数据格式或错误结构: {containers_data}"
        app.logger.error(incus_error_message)
        app.logger.warning("无法解析 Incus 列表，尝试从数据库加载容器列表。")
        for name, data in db_containers_dict.items():
            listed_containers.append({
                'name': name,
                'status': data.get('status', '未知 (来自数据库)'),
                'image_source': data.get('image_source', 'N/A (来自数据库)'),
                'ip': 'N/A (数据库信息)',
                'created_at': data.get('created_at', 'N/A (来自数据库)')
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
        image_error_message = images_data if not success_img else 'Incus 返回了无效的镜像数据格式。'
        app.logger.error(f"获取镜像列表失败: {image_error_message}")

    return render_template('index.html',
                           containers=listed_containers,
                           images=available_images,
                           incus_error=(incus_error, incus_error_message),
                           image_error=(image_error, image_error_message))


@app.route('/container/create', methods=['POST'])
@web_or_api_authentication_required
def create_container():
    name = request.form.get('name')
    image = request.form.get('image')
    if not name or not image:
        return jsonify({'status': 'error', 'message': '容器名称和镜像不能为空'}), 400

    db_exists = query_db('SELECT 1 FROM containers WHERE incus_name = ?', [name], one=True)
    if db_exists:
        app.logger.warning(f"Attempted to create container {name} which already exists in DB.")
        return jsonify({'status': 'error', 'message': f'名称为 "{name}" 的容器在数据库中已存在记录。请尝试刷新列表或使用其他名称。'}), 409


    success, output = run_incus_command(['launch', image, name], parse_json=False, timeout=120)

    if success:
        time.sleep(5)

        _, list_output = run_incus_command(['list', name, '--format', 'json'])

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
             app.logger.info(f"Successfully got list info for new container {name} after launch.")
        else:
             app.logger.warning(f"Failed to get list info for new container {name} after launch. list output: {list_output}")

        sync_container_to_db(name, image_source_desc, status_val, created_at)

        return jsonify({'status': 'success', 'message': f'容器 {name} 创建并启动操作已提交。状态将很快同步。'}), 200
    else:
        app.logger.error(f"Failed to launch container {name}: {output}")
        return jsonify({'status': 'error', 'message': f'创建容器 {name} 失败: {output}'}), 500


@app.route('/container/<name>/action', methods=['POST'])
@web_or_api_authentication_required
def container_action(name):
    action = request.form.get('action')
    commands = {
        'start': ['start', name],
        'stop': ['stop', name, '--force'],
        'restart': ['restart', name, '--force'],
    }

    if action == 'delete':
        app.logger.info(f"Attempting to delete container {name} and its associated NAT rules.")

        success_db_rules, rules = get_nat_rules_for_container(name)
        if not success_db_rules:
             app.logger.error(f"Failed to fetch NAT rules for container {name} before deletion: {rules}")
             return jsonify({'status': 'error', 'message': f'删除容器前从数据库获取NAT规则失败: {rules}'}), 500

        failed_rule_deletions = []
        warning_rule_deletions = []
        if rules:
            app.logger.info(f"Found {len(rules)} associated NAT rules in DB for {name}. Attempting iptables delete...")
            for rule in rules:
                if not all(key in rule for key in ['id', 'host_port', 'container_port', 'protocol', 'ip_at_creation']):
                     app.logger.error(f"Incomplete NAT rule details in DB for deletion, skipping iptables delete for rule: {rule}")
                     failed_rule_deletions.append(f"Rule ID {rule.get('id', 'N/A')} (数据库记录不完整)")
                     continue

                success_iptables_delete, iptables_message, is_bad_rule = perform_iptables_delete_for_rule(rule)

                if not success_iptables_delete:
                    if is_bad_rule:
                         warning_rule_deletions.append(iptables_message)
                         app.logger.warning(f"IPTables delete failed with 'Bad rule' for rule ID {rule.get('id', 'N/A')}: {iptables_message}. Proceeding with DB delete.")
                         db_success, db_msg = remove_nat_rule_from_db(rule['id'])
                         if not db_success:
                              app.logger.error(f"IPTables rule deletion reported 'Bad rule' for ID {rule['id']}, but failed to remove record from DB: {db_msg}")
                    else:
                         failed_rule_deletions.append(iptables_message)
                         app.logger.error(f"IPTables delete failed (not Bad rule) for rule ID {rule.get('id', 'N/A')}: {iptables_message}. Aborting container delete attempt for this rule.")

                else:
                    db_success, db_msg = remove_nat_rule_from_db(rule['id'])
                    if not db_success:
                        app.logger.error(f"IPTables rule deleted for ID {rule['id']}, but failed to remove record from DB: {db_msg}")

        if failed_rule_deletions:
            error_message = f"删除容器 {name} 前，未能移除所有关联的 NAT 规则 ({len(failed_rule_deletions)}/{len(rules) if rules else 0} 条 iptables 删除失败)。请手动检查 iptables。<br>失败详情: " + "; ".join(failed_rule_deletions)
            if warning_rule_deletions:
                 error_message += "<br>跳过的规则 (iptables 未找到): " + "; ".join(warning_rule_deletions)
            app.logger.error(error_message)
            return jsonify({'status': 'error', 'message': error_message}), 500

        app.logger.info(f"All {len(rules) if rules else 0} associated NAT rules for {name} successfully handled for iptables delete (or none existed). Proceeding with Incus container deletion.")
        success_incus_delete, incus_output = run_incus_command(['delete', name, '--force'], parse_json=False, timeout=120)

        if success_incus_delete:
            remove_container_from_db(name)
            message = f'容器 {name} 及其关联的 {len(rules) if rules else 0} 条 NAT 规则记录已成功删除。'
            if warning_rule_deletions:
                 message += "<br>注意: 部分 iptables 规则在删除时已不存在。"
            app.logger.info(message)
            return jsonify({'status': 'success', 'message': message}), 200
        else:
            error_message = f'删除容器 {name} 失败: {incus_output}'
            app.logger.error(error_message)
            return jsonify({'status': 'error', 'message': error_message}), 500

    if action not in commands:
        return jsonify({'status': 'error', 'message': '无效的操作'}), 400

    timeout_val = 60
    if action in ['stop', 'restart']: timeout_val = 120

    success, output = run_incus_command(commands[action], parse_json=False, timeout=timeout_val)

    if success:
        message = f'容器 {name} {action} 操作提交成功。'
        time.sleep(action in ['stop', 'restart', 'start'] and 3 or 1)

        _, list_output = run_incus_command(['list', name, '--format', 'json'], timeout=10)

        new_status_val = '未知'
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

        return jsonify({'status': 'success', 'message': message}), 200
    else:
        app.logger.error(f"Incus action '{action}' failed for {name}: {output}")
        return jsonify({'status': 'error', 'message': f'容器 {name} {action} 操作失败: {output}'}), 500


@app.route('/container/<name>/exec', methods=['POST'])
@web_or_api_authentication_required
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

    success, output = run_incus_command(['exec', name, '--'] + command_parts, parse_json=False, timeout=120)

    if success:
        return jsonify({'status': 'success', 'output': output}), 200
    else:
        return jsonify({'status': 'error', 'output': output, 'message': '命令执行失败'}), 500


@app.route('/container/<name>/info')
@web_or_api_authentication_required
def container_info(name):
    info_output, error_message = _get_container_raw_info(name)

    if info_output is None:
        return jsonify({'status': 'NotFound', 'message': error_message}), 404
    else:
        response_data = info_output
        return jsonify(response_data), 200


@app.route('/container/<name>/add_nat_rule', methods=['POST'])
@web_or_api_authentication_required
def add_nat_rule(name):
    host_port_str = request.form.get('host_port')
    container_port_str = request.form.get('container_port')
    protocol = request.form.get('protocol')

    if not host_port_str or not container_port_str or not protocol:
         return jsonify({'status': 'error', 'message': '主机端口、容器端口和协议不能为空'}), 400
    try:
        host_port = int(host_port_str)
        container_port = int(container_port_str)
        if not (1 <= host_port <= 65535) or not (1 <= container_port <= 65535):
            raise ValueError("端口号必须在 1 到 65535 之间。")
    except ValueError as e:
         return jsonify({'status': 'error', 'message': f'端口号无效: {e}'}), 400

    if protocol not in ['tcp', 'udp']:
         return jsonify({'status': 'error', 'message': '协议必须是 tcp 或 udp'}), 400

    db_check_success, rule_exists = check_nat_rule_exists_in_db(name, host_port, protocol)
    if not db_check_success:
        app.logger.error(f"检查现有 NAT 规则记录失败: {rule_exists}")
        return jsonify({'status': 'error', 'message': f"检查现有 NAT 规则记录失败: {rule_exists}"}), 500
    if rule_exists:
        message = f'容器 {name} 的主机端口 {host_port}/{protocol} NAT 规则已存在记录，跳过添加。'
        app.logger.warning(message)
        return jsonify({'status': 'warning', 'message': message}), 200

    container_info_data, info_error_message = _get_container_raw_info(name)

    if container_info_data is None:
         return jsonify({'status': 'error', 'message': f'无法获取容器 {name} 信息: {info_error_message}'}), 404

    if container_info_data.get('status') != 'Running':
         status_msg = container_info_data.get('status', '未知')
         return jsonify({'status': 'error', 'message': f'容器 {name} 必须处于 Running 状态才能添加 NAT 规则 (当前状态: {status_msg})。'}), 400

    container_ip = container_info_data.get('ip')

    if not container_ip or container_ip == 'N/A':
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

    app.logger.info(f"Adding NAT rule via iptables: {' '.join(shlex.quote(part) for part in iptables_command)}")

    success_iptables, output = run_command(iptables_command, parse_json=False)

    if success_iptables:
        rule_details = {
             'container_name': name,
             'host_port': host_port,
             'container_port': container_port,
             'protocol': protocol,
             'ip_at_creation': container_ip
        }
        db_success, db_result = add_nat_rule_to_db(rule_details)

        message = f'已成功为容器 {name} 添加 NAT 规则: 主机端口 {host_port}/{protocol} 转发到容器 IP {container_ip} 端口 {container_port}。'

        if not db_success:
             message += f" 但记录规则到数据库失败: {db_result}"
             app.logger.error(f"Failed to record NAT rule for {name} in DB after successful iptables: {db_result}")
             return jsonify({'status': 'warning', 'message': message}), 200

        return jsonify({'status': 'success', 'message': message, 'rule_id': db_result}), 200

    else:
        message = f'添加 NAT 规则失败: {output}'
        app.logger.error(f"iptables command failed for {name}: {output}")
        return jsonify({'status': 'error', 'message': message}), 500

@app.route('/container/<name>/nat_rules', methods=['GET'])
@web_or_api_authentication_required
def list_nat_rules(name):
    success, rules = get_nat_rules_for_container(name)
    if success:
        return jsonify({'status': 'success', 'rules': rules}), 200
    else:
        return jsonify({'status': 'error', 'message': rules}), 500

@app.route('/container/nat_rule/<int:rule_id>', methods=['DELETE'])
@web_or_api_authentication_required
def delete_nat_rule(rule_id):
    app.logger.info(f"Attempting to delete NAT rule ID {rule_id}.")
    success_db, rule = get_nat_rule_by_id(rule_id)

    if not success_db:
         app.logger.error(f"Error fetching rule ID {rule_id} from DB for deletion: {rule}")
         return jsonify({'status': 'error', 'message': f'删除NAT规则前从数据库获取规则失败: {rule}'}), 500

    if not rule:
        app.logger.warning(f"NAT rule ID {rule_id} not found in DB for deletion.")
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

    success_iptables, iptables_message, is_bad_rule = perform_iptables_delete_for_rule(rule_details_for_iptables)

    if success_iptables or is_bad_rule:
        db_success, db_message = remove_nat_rule_from_db(rule_id)

        message = f'已成功删除ID为 {rule_id} 的NAT规则记录。'
        if is_bad_rule:
             message = f'数据库记录已删除 (ID {rule_id})。注意：该规则在 iptables 中未找到或已不存在。'

        if not db_success:
             message += f" 但从数据库移除记录失败: {db_message}"
             app.logger.error(f"IPTables rule deletion succeeded or was 'Bad rule' for ID {rule['id']}, but failed to remove record from DB: {db_message}")
             return jsonify({'status': 'warning', 'message': message}), 200

        return jsonify({'status': 'success', 'message': message}), 200
    else:
        message = f'删除ID为 {rule_id} 的NAT规则失败: {iptables_message}'
        app.logger.error(f"iptables delete command failed for rule ID {rule_id}: {iptables_message}")
        return jsonify({'status': 'error', 'message': message}), 500


def main():
    print("\n============================================")
    print(" Incus Web 管理器启动信息")
    print("============================================")

    if not os.path.exists(DATABASE_NAME):
        print(f"错误：数据库文件 '{DATABASE_NAME}' 未找到。")
        print("请先运行 'python init_db.py' 来初始化数据库。")
        sys.exit(1)

    if not load_settings_from_db():
        print("错误：无法从数据库加载所有必需的设置。请检查数据库和 init_db.py 运行情况。")
        sys.exit(1)

    admin_username = SETTINGS.get('admin_username', 'N/A')
    api_key_hash = SETTINGS.get('api_key_hash', 'N/A')

    print(f"管理员用户名: {admin_username} (从数据库加载)")
    print(f"API 密钥哈希: {api_key_hash} (从数据库加载)")
    print("--------------------------------------------")
    print("API 调用方法:")
    print("API 请求 Headers 应包含:")
    print(f"  X-API-Key-Hash: [您的 API 密钥明文的 SHA256 十六进制哈希值]")
    print("============================================\n")


    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='containers';")
        if not cursor.fetchone():
            print(f"错误：数据库表 'containers' 在 '{DATABASE_NAME}' 中未找到。")
            print("请确保 'python init_db.py' 已成功运行并创建了表结构。")
            sys.exit(1)

        cursor.execute("PRAGMA table_info(containers);")
        containers_columns_info = cursor.fetchall()
        containers_column_names = [col[1] for col in containers_columns_info]
        required_container_columns = ['incus_name', 'status', 'created_at', 'image_source', 'last_synced']
        missing_container_columns = [col for col in required_container_columns if col not in containers_column_names]
        if missing_container_columns:
            print(f"错误：数据库表 'containers' 缺少必需的列: {', '.join(missing_container_columns)}")
            print("请确保 'python init_db.py' 已成功运行并创建了正确的表结构。")
            sys.exit(1)

        cursor.execute("PRAGMA index_list(containers);")
        indexes = cursor.fetchall()
        has_unique_incus_name = False
        for idx in indexes:
            if idx[2] == 1:
                cursor.execute(f"PRAGMA index_info('{idx[1]}');")
                idx_cols = [col[2] for col in cursor.fetchall()]
                if len(idx_cols) == 1 and idx_cols[0] == 'incus_name':
                     has_unique_incus_name = True
                     break

        if not has_unique_incus_name:
             print("警告：数据库表 'containers' 的 'incus_name' 列可能没有 UNIQUE约束。这可能导致同步问题。")


        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nat_rules';")
        if not cursor.fetchone():
             print(f"错误：数据库表 'nat_rules'在 '{DATABASE_NAME}'中未找到。")
             print("请确保 'python init_db.py' 已成功运行并创建了表结构，包含 'nat_rules' 表。")
             sys.exit(1)

        cursor.execute("PRAGMA table_info(nat_rules);")
        nat_columns_info = cursor.fetchall()
        nat_column_names = [col[1] for col in nat_columns_info]
        required_nat_columns = ['container_name', 'host_port', 'container_port', 'protocol', 'ip_at_creation', 'created_at']
        missing_nat_columns = [col for col in required_nat_columns if col not in nat_column_names]
        if missing_nat_columns:
            print(f"错误：数据库表 'nat_rules' 缺少必需的列: {', '.join(missing_nat_columns)}")
            print("请确保 'python init_db.py' 已成功运行并创建了正确的表结构。")
            sys.exit(1)

        cursor.execute("PRAGMA index_list(nat_rules);")
        indexes = cursor.fetchall()
        unique_composite_index_exists = False
        for index_info in indexes:
            if index_info[2] == 1:
                index_name = index_info[1]
                cursor.execute(f"PRAGMA index_info('{index_name}');")
                index_cols = sorted([col[2] for col in cursor.fetchall()])
                if index_cols == ['container_name', 'host_port', 'protocol']:
                     unique_composite_index_exists = True
                     break

        if not unique_composite_index_exists:
             print("警告：数据库表 'nat_rules' 可能缺少 UNIQUE (container_name, host_port, protocol) 约束。这可能导致重复规则记录。建议手动检查或重建表。")

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings';")
        if not cursor.fetchone():
            print(f"错误：数据库表 'settings' 在 '{DATABASE_NAME}' 中未找到。")
            print("请确保 'python init_db.py' 已成功运行并创建了表结构。")
            sys.exit(1)


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
    except FileNotFoundError:
         print("警告：'iptables' 命令未找到。NAT 功能可能无法使用。")
    except subprocess.CalledProcessError as e:
         print(f"警告：执行 'iptables --version' 失败 (退出码 {e.returncode}): {e.stderr.strip()}")
         print("iptables 命令可能存在问题或权限不足。")
    except subprocess.TimeoutExpired:
         print("警告：执行 'iptables --version' 超时。")
    except Exception as e:
         print(f"启动时 iptables 检查发生异常: {e}")


    print("启动 Flask Web 服务器...")
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()
