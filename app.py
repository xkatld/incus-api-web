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
            # For non-JSON output, return True and the stripped stdout on success
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
                # Attempt to parse various ISO 8601 formats
                if created_at_to_db.endswith('Z'):
                   created_at_to_db = created_at_to_db[:-1] + '+00:00'

                tz_match_hhmm = re.search(r'([+-])(\d{4})$', created_at_to_db)
                if tz_match_hhmm:
                    sign = tz_match_hhmm.group(1)
                    hhmm = tz_match_hhmm.group(2)
                    created_at_to_db = created_at_to_db[:-4] + f"{sign}{hhmm[:2]}:{hhmm[2:]}"

                # Truncate microseconds if more than 6 digits
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
                    else: # No timezone part after microseconds
                        if len(time_tz_part) > 6:
                            time_tz_part = time_tz_part[:6]

                    created_at_to_db = parts[0] + '.' + time_tz_part
                # Add microseconds if missing but timezone is present (e.g., 2023-01-01T10:00:00+08:00)
                elif re.search(r'[+-]\d{2}:?\d{2}$', created_at_to_db):
                     time_segment = created_at_to_db.split('T')[-1]
                     if '.' not in time_segment.split(re.search(r'[+-]', time_segment).group(0))[0]: # Check if '.' is missing before timezone
                           tz_part = re.search(r'[+-]\d{2}:?\d{2}$', created_at_to_db).group(0)
                           if '.' not in created_at_to_db: # Ensure we don't double add if it had '.' already
                              created_at_to_db = created_at_to_db.replace(tz_part, '.000000' + tz_part)


                # Validate the format by attempting to parse
                datetime.datetime.fromisoformat(created_at_to_db)

            except (ValueError, AttributeError, TypeError) as ve:
                # Fallback if parsing fails
                app.logger.warning(f"无法精确解析 Incus 创建时间 '{original_created_at_to_db}' for {name} 为 ISO 格式 ({ve}). 将尝试使用数据库记录的原值或当前时间.")
                old_db_entry = query_db('SELECT created_at FROM containers WHERE incus_name = ?', [name], one=True)
                if old_db_entry and old_db_entry['created_at']:
                     try:
                          # Try parsing the old DB value in case it was correct
                          datetime.datetime.fromisoformat(old_db_entry['created_at'])
                          created_at_to_db = old_db_entry['created_at']
                          app.logger.info(f"使用数据库记录的创建时间 '{created_at_to_db}' for {name}.")
                     except (ValueError, TypeError):
                          app.logger.warning(f"数据库记录的创建时间 '{old_db_entry['created_at']}' for {name} 也是无效 ISO 格式.")
                          created_at_to_db = datetime.datetime.now().isoformat() # Fallback to current time
                          app.logger.info(f"使用当前时间作为创建时间 for {name}.")
                else:
                     created_at_to_db = datetime.datetime.now().isoformat() # Fallback to current time
                     app.logger.info(f"使用当前时间作为创建时间 for {name} (Incus did not provide created_at).")

        else:
             # Fallback if created_at_str is None
             old_db_entry = query_db('SELECT created_at FROM containers WHERE incus_name = ?', [name], one=True)
             if old_db_entry and old_db_entry['created_at']:
                 try:
                      datetime.datetime.fromisoformat(old_db_entry['created_at'])
                      created_at_to_db = old_db_entry['created_at']
                      app.logger.info(f"使用数据库记录的创建时间 '{created_at_to_db}' for {name} (Incus did not provide created_at).")
                 except (ValueError, TypeError):
                      app.logger.warning(f"数据库记录的创建时间 '{old_db_entry['created_at']}' for {name} 也是无效 ISO 格式 (Incus did not provide created_at).")
                      created_at_to_db = datetime.datetime.now().isoformat() # Fallback to current time
                      app.logger.info(f"使用当前时间作为创建时间 for {name} (Incus did not provide created_at).")
             else:
                  created_at_to_db = datetime.datetime.now().isoformat() # Fallback to current time
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
        query_db('DELETE FROM containers WHERE incus_name = ?', [name])
        # Associated NAT rules are also deleted here
        query_db('DELETE FROM nat_rules WHERE container_name = ?', [name])
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

def check_nat_rule_exists_in_db(container_name, host_port, protocol):
    """Checks if a NAT rule record exists in the database."""
    try:
        # Check for an existing rule with the same container, host port, and protocol
        rule = query_db('''
            SELECT id FROM nat_rules
            WHERE container_name = ? AND host_port = ? AND protocol = ?
        ''', (container_name, host_port, protocol), one=True)
        # Return True, boolean result (True if rule exists, False otherwise)
        return True, rule is not None
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 check_nat_rule_exists_in_db for {container_name}, host={host_port}/{protocol}: {e}")
        # Return False and the error message to indicate a database failure
        return False, f"检查规则记录失败: {e}"


def add_nat_rule_to_db(rule_details):
    """Adds a NAT rule record to the database."""
    # rule_details should be a dict with keys: container_name, host_port, container_port, protocol, ip_at_creation
    try:
        query_db('''
            INSERT INTO nat_rules (container_name, host_port, container_port, protocol, ip_at_creation)
            VALUES (?, ?, ?, ?, ?)
        ''', (rule_details['container_name'], rule_details['host_port'],
              rule_details['container_port'], rule_details['protocol'],
              rule_details['ip_at_creation']))
        app.logger.info(f"Added NAT rule to DB: {rule_details['container_name']}, host={rule_details['host_port']}/{rule_details['protocol']}, container={rule_details['ip_at_creation']}:{rule_details['container_port']}")
        return True, "规则记录成功添加到数据库。"
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 add_nat_rule_to_db for {rule_details.get('container_name', 'N/A')}: {e}")
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

def cleanup_orphaned_nat_rules_in_db(existing_incus_container_names):
    """Removes NAT rules from the DB whose containers no longer exist in Incus."""
    try:
        # Get all unique container names from the nat_rules table
        db_rule_container_names_rows = query_db('SELECT DISTINCT container_name FROM nat_rules')
        db_rule_container_names = {row['container_name'] for row in db_rule_container_names_rows}

        # Find container names in DB rules that are NOT in the list of existing Incus containers
        orphaned_names = [
            name for name in db_rule_container_names
            if name not in existing_incus_container_names
        ]

        if orphaned_names:
            app.logger.warning(f"检测到数据库中存在孤立的NAT规则记录，对应的容器已不存在于Incus: {orphaned_names}")
            # Delete NAT rules for these orphaned container names
            # Using execute_many would be more efficient for many names
            placeholders = ','.join('?' * len(orphaned_names))
            query = f'DELETE FROM nat_rules WHERE container_name IN ({placeholders})'
            query_db(query, orphaned_names)
            app.logger.info(f"已从数据库中移除 {len(orphaned_names)} 个孤立容器 ({len(db_rule_container_names) - len(orphaned_names)} 个现有容器) 的NAT规则记录。")
            # Also remove the container record itself if it still exists in the containers table (should have been removed by sync already, but double check)
            container_placeholders = ','.join('?' * len(orphaned_names))
            container_query = f'DELETE FROM containers WHERE incus_name IN ({container_placeholders})'
            query_db(container_query, orphaned_names)
            app.logger.info(f"已从数据库中移除 {len(orphaned_names)} 个孤立容器的容器记录 (如果存在)。")

    except sqlite3.Error as e:
        app.logger.error(f"数据库错误 cleanup_orphaned_nat_rules_in_db: {e}")
    except Exception as e:
        app.logger.error(f"清理孤立NAT规则时发生异常: {e}")


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

    incus_container_names_set = set()

    if not success:
        incus_error = True
        incus_error_message = containers_data
        app.logger.warning(f"无法从 Incus 获取容器列表 ({incus_error_message})，尝试从数据库加载。")
        # When Incus list fails, we can't trust the live state (status, IP, etc.)
        # Show containers from DB, but mark them as potentially stale
        for name, data in db_containers_dict.items():
            listed_containers.append({
                'name': name,
                'status': data.get('status', 'Unknown (from DB)'),
                'image_source': data.get('image_source', 'N/A (from DB)'),
                'ip': 'N/A (DB info)', # Cannot reliably get live IP without Incus list
                'created_at': data.get('created_at', 'N/A (from DB)')
            })
            # We don't have live names, so we can't perform the primary sync or orphan cleanup accurately here.
            # The best we can do is show what we have in the DB.

    elif isinstance(containers_data, list):
        # Incus list succeeded, perform sync and cleanup
        for item in containers_data:
            if not isinstance(item, dict) or 'name' not in item:
                app.logger.warning(f"Skipping invalid item in containers_data: {item}")
                continue

            item_name = item['name']
            incus_container_names_set.add(item_name) # Add to set of live Incus names

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
                         # Check common container network interfaces and ensure it's a dict
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
                                             ip_address = addr.split('/')[0] # Get IP without mask
                                             found_ip = True
                                             break # Found a global IPv4, move to next container item
                                 if found_ip: break # Found a global IPv4 on this interface, move to next interface/container item


            container_info = {
                'name': item_name,
                'status': item.get('status', 'Unknown'),
                'image_source': image_source,
                'ip': ip_address, # Display live IP if available
                'created_at': created_at_str,
            }
            listed_containers.append(container_info)
            # Sync this live container's info to the database
            sync_container_to_db(item_name, image_source, item.get('status', 'Unknown'), created_at_str)

        # --- Primary Sync: Remove DB entries for containers no longer in Incus ---
        # Get all names currently in the 'containers' table in the DB
        current_db_names = {row['incus_name'] for row in query_db('SELECT incus_name FROM containers')}
        # Find names in the DB that are not in the live Incus list
        vanished_names_from_db = [db_name for db_name in current_db_names if db_name not in incus_container_names_set]
        for db_name in vanished_names_from_db:
             # remove_container_from_db also removes associated NAT rules
             remove_container_from_db(db_name)
             app.logger.info(f"根据 Incus 列表移除数据库中不存在的容器和NAT规则记录: {db_name}")


        # --- Secondary Cleanup: Remove Orphaned NAT Rules ---
        # This catches NAT rules whose container_name might exist in nat_rules
        # but for some reason the container wasn't in the Incus list
        # and perhaps its entry wasn't properly removed from the 'containers' table earlier (less likely with the above sync)
        # but serves as a safety net directly on the nat_rules table.
        cleanup_orphaned_nat_rules_in_db(incus_container_names_set)


    else:
        # Incus list returned something unexpected and not an error string
        incus_error = True
        incus_error_message = f"Incus list 返回了未知数据格式或错误结构: {containers_data}"
        app.logger.error(incus_error_message)
        app.logger.warning("无法解析 Incus 列表，尝试从数据库加载容器列表。")
        # Fallback to showing only DB data without live status/IP
        for name, data in db_containers_dict.items():
            listed_containers.append({
                'name': name,
                'status': data.get('status', 'Unknown (from DB)'),
                'image_source': data.get('image_source', 'N/A (from DB)'),
                'ip': 'N/A (DB info)',
                'created_at': data.get('created_at', 'N/A (from DB)')
            })
        # Cannot perform orphan cleanup as we don't have reliable live Incus names


    # Fetch available images
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
                # Find the first alias with a 'name'
                alias_entry = next((a for a in aliases if isinstance(a, dict) and a.get('name')), None)
                if alias_entry:
                     alias_name = alias_entry.get('name')

            # If no alias with a name, use fingerprint prefix
            if not alias_name:
                fingerprint = img.get('fingerprint')
                alias_name = fingerprint[:12] if isinstance(fingerprint, str) else 'unknown_image'

            # Get description from properties
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

    # Basic check if container name already exists in DB before attempting launch
    db_exists = query_db('SELECT 1 FROM containers WHERE incus_name = ?', [name], one=True)
    if db_exists:
        # Can optionally check against live Incus list too if needed
        # success_live, live_list = run_incus_command(['list', name, '--format', 'json'])
        # if success_live and isinstance(live_list, list) and len(live_list) > 0:
        #     return jsonify({'status': 'error', 'message': f'名称为 "{name}" 的容器已存在。'}), 409 # Conflict
        # else:
        #     # DB says it exists, but live list doesn't confirm or failed. Proceed with caution?
        #     pass # Let the launch command fail

        return jsonify({'status': 'error', 'message': f'名称为 "{name}" 的容器在数据库中已存在记录。请尝试刷新列表或使用其他名称。'}), 409


    success, output = run_incus_command(['launch', image, name], parse_json=False, timeout=120)

    if success:
        time.sleep(5) # Give container a moment to start and get IP

        # Attempt to get latest info after launch
        _, list_output = run_incus_command(['list', name, '--format', 'json'])

        created_at = None
        image_source_desc = image # Start with requested image name
        status_val = 'Pending' # Start with a likely status

        if isinstance(list_output, list) and len(list_output) > 0 and isinstance(list_output[0], dict):
             container_data = list_output[0]
             status_val = container_data.get('status', status_val) # Update status if available
             created_at = container_data.get('created_at') # Update created_at if available
             list_cfg = container_data.get('config')
             if isinstance(list_cfg, dict):
                  list_img_desc = list_cfg.get('image.description')
                  if list_img_desc: image_source_desc = list_img_desc # Use image description if available
             app.logger.info(f"Successfully got list info for new container {name} after launch.")
        else:
             app.logger.warning(f"Failed to get list info for new container {name} after launch. list output: {list_output}")

        # Sync the newly created container's info to the database
        sync_container_to_db(name, image_source_desc, status_val, created_at)

        return jsonify({'status': 'success', 'message': f'容器 {name} 创建并启动操作已提交。状态将很快同步。'})
    else:
        # If launch failed, do not add to DB (or consider removing if it was partially created)
        # Assuming launch command cleans up after itself on failure
        app.logger.error(f"Failed to launch container {name}: {output}")
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
            # If deletion was successful, remove from DB (which also removes NAT rules)
            remove_container_from_db(name)
            message = f'容器 {name} 已删除。'
        else:
            # For start/stop/restart, attempt to get latest status after action
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
                 message = f'容器 {name} {action} 操作提交成功，但无法获取最新状态（list命令失败或容器状态未立即更新）。'
                 app.logger.warning(f"Failed to get updated status for {name} after {action}. list output: {list_output}")

            # Sync updated status (and potentially other info) to DB
            sync_container_to_db(name, db_image_source, new_status_val, db_created_at)


        return jsonify({'status': 'success', 'message': message})
    else:
        # If the Incus command failed, report the error
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
            'message': '数据主要来自 Incus 实时信息。',
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
                                        break # Found a global IPv4, stop looking
                            if info_output['ip'] != 'N/A': break # Found IP, stop looking on other interfaces


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

    # --- Check if rule already exists in DB *before* iptables ---
    db_check_success, rule_exists = check_nat_rule_exists_in_db(name, host_port, protocol)
    if not db_check_success:
        app.logger.error(f"检查现有 NAT 规则记录失败: {rule_exists}") # rule_exists contains the error message here
        return jsonify({'status': 'error', 'message': f"检查现有 NAT 规则记录失败: {rule_exists}"}), 500
    if rule_exists: # Rule already exists in DB
        # If it's in the DB, we assume it was successfully added to iptables previously.
        # Don't attempt to add to iptables or DB again.
        message = f'容器 {name} 的主机端口 {host_port}/{protocol} NAT 规则已存在记录，跳过添加。'
        app.logger.warning(message)
        # Return warning status so the frontend can show a different message
        return jsonify({'status': 'warning', 'message': message, 'output': ''}), 200


    # Check if the container is running
    _, list_output = run_incus_command(['list', name, '--format', 'json'], timeout=5)
    container_status = 'Unknown'
    # Attempt to get live status first
    if isinstance(list_output, list) and len(list_output) > 0 and isinstance(list_output[0], dict):
         container_status = list_output[0].get('status', 'Unknown')
    else:
         # Fallback to DB status if list fails, but warn it might be stale
         db_info = query_db('SELECT status FROM containers WHERE incus_name = ?', [name], one=True)
         if db_info:
             container_status = db_info['status']
             app.logger.warning(f"Could not get live status for {name}, falling back to DB status: {container_status}")
         else:
            # If not in live list and not in DB, container likely doesn't exist
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
    success_iptables, output = run_command(iptables_command, parse_json=False) # output will be empty string on success

    if success_iptables:
        # If iptables command succeeded, add the rule to the database record
        rule_details = {
             'container_name': name,
             'host_port': host_port,
             'container_port': container_port,
             'protocol': protocol,
             'ip_at_creation': container_ip # Store the IP used for the rule
        }
        db_success, db_message = add_nat_rule_to_db(rule_details)
        message = f'已成功为容器 {name} 添加 NAT 规则: 主机端口 {host_port}/{protocol} 转发到容器 IP {container_ip} 端口 {container_port}。'

        if not db_success:
             # This case should be rare with the DB check upfront, but possible in theory (e.g., concurrent adds)
             message += f" 但记录规则到数据库失败: {db_message}"
             app.logger.error(f"Failed to record NAT rule for {name} in DB after successful iptables: {db_message}")
             # Return 200 with warning status, as the primary action (iptables) succeeded
             return jsonify({'status': 'warning', 'message': message, 'output': output})

        # Both iptables and DB insertion successful
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
        # Return raw data, formatting will be done in frontend
        return jsonify({'status': 'success', 'rules': rules})
    else:
        return jsonify({'status': 'error', 'message': rules}), 500

@app.route('/container/nat_rule/<int:rule_id>', methods=['DELETE'])
def delete_nat_rule(rule_id):
    """API endpoint to delete a NAT rule by its ID."""
    # Get rule details from DB to construct the iptables command
    success_db, rule = get_nat_rule_by_id(rule_id)

    if not success_db:
         app.logger.error(f"Error fetching rule ID {rule_id} from DB: {rule}")
         return jsonify({'status': 'error', 'message': rule}), 500

    if not rule:
        app.logger.warning(f"NAT rule ID {rule_id} not found in DB for deletion.")
        return jsonify({'status': 'error', 'message': f'数据库中找不到ID为 {rule_id} 的NAT规则记录，可能已被手动删除。'}), 404

    container_name = rule.get('container_name', 'unknown')
    host_port = rule['host_port']
    container_port = rule['container_port']
    protocol = rule['protocol']
    ip_at_creation = rule['ip_at_creation'] # Use the IP recorded at creation time

    # Construct the iptables command to delete the rule
    # Use the exact parameters used for insertion to match the rule precisely
    # Deleting a DNAT rule requires matching the parameters used when it was added (-p, --dport, -j DNAT, --to-destination).
    # The --to-destination includes the target IP and port. We must use the IP recorded at creation time
    # because the container's IP might have changed since the rule was added, but the iptables rule
    # refers to the IP it was told to forward *to* at the time of creation.

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
    success_iptables, output = run_command(iptables_command, parse_json=False) # output will be empty string on success

    if success_iptables:
        # If iptables deletion was successful, remove the record from the database
        db_success, db_message = remove_nat_rule_from_db(rule_id)
        message = f'已成功删除ID为 {rule_id} 的NAT规则。IPTABLES 输出:\n{output}' # Include iptables output even on success
        if not db_success:
             message += f" 但从数据库移除记录失败: {db_message}"
             app.logger.error(f"Failed to remove NAT rule ID {rule_id} from DB after successful iptables: {db_message}")
             # Return 200 with warning status as primary action succeeded
             return jsonify({'status': 'warning', 'message': message, 'output': output})


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
        cursor.execute("PRAGMA index_list(containers);")
        indexes = cursor.fetchall()
        has_unique_incus_name = any(idx[2] == 1 and idx[1] == 'sqlite_autoindex_containers_1' for idx in indexes) # Default unique index name
        if not has_unique_incus_name:
             # More thorough check for any unique index on incus_name
             for idx in indexes:
                 if idx[2] == 1:
                     cursor.execute(f"PRAGMA index_info('{idx[1]}');")
                     idx_cols = [col[2] for col in cursor.fetchall()]
                     if len(idx_cols) == 1 and idx_cols[0] == 'incus_name':
                          has_unique_incus_name = True
                          break

             if not has_unique_incus_name:
                 print("警告：数据库表 'containers' 的 'incus_name' 列可能没有 UNIQUE 约束。这可能导致同步问题。")
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
                # Get column names involved in this unique index and sort them
                index_cols = sorted([col[2] for col in cursor.fetchall()])
                # Check if the sorted column list matches the required composite key
                if index_cols == ['container_name', 'host_port', 'protocol']:
                     unique_composite_index_exists = True
                     break
        if not unique_composite_index_exists:
             print("警告：数据库表 'nat_rules' 可能缺少 UNIQUE (container_name, host_port, protocol) 约束。这可能导致重复规则记录。建议手动检查或重建表。")


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
    # Change debug=False for production!
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()
