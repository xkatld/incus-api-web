import sqlite3
import logging
import datetime
import re
from config import DATABASE_NAME

logger = logging.getLogger(__name__)

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
        logger.error(f"数据库查询错误: {e}\nQuery: {query}\nArgs: {args}")
        rv = []
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()
    return (rv[0] if rv else None) if one else rv

def load_settings_from_db():
    try:
        settings_rows = query_db('SELECT key, value FROM settings')
        if not settings_rows:
            logger.error("从数据库加载设置失败: 'settings' 表为空或不存在。请运行 init_db.py。")
            return None
        
        settings_dict = {row['key']: row['value'] for row in settings_rows}
        required_keys = ['admin_username', 'admin_password_hash', 'api_key_hash']
        
        for key in required_keys:
            if key not in settings_dict:
                logger.error(f"从数据库加载设置失败: 缺少键 '{key}'。请运行 init_db.py 检查设置。")
                return None
                
        logger.info("从数据库成功加载设置。")
        return settings_dict
    except sqlite3.OperationalError:
        logger.error("从数据库加载设置失败: 'settings' 表不存在。请运行 init_db.py。")
        return None
    except Exception as e:
        logger.error(f"加载设置时发生异常: {e}")
        return None

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
                        if len(micro_part) > 6: micro_part = micro_part[:6]
                        time_tz_part = micro_part + tz_part
                    else:
                        if len(time_tz_part) > 6: time_tz_part = time_tz_part[:6]
                    created_at_to_db = parts[0] + '.' + time_tz_part
                elif re.search(r'[+-]\d{2}:?\d{2}$', created_at_to_db):
                    time_segment = created_at_to_db.split('T')[-1]
                    if '.' not in time_segment.split(re.search(r'[+-]', time_segment).group(0))[0]:
                        tz_part = re.search(r'[+-]\d{2}:?\d{2}$', created_at_to_db).group(0)
                        if '.' not in created_at_to_db:
                            created_at_to_db = created_at_to_db.replace(tz_part, '.000000' + tz_part)
                datetime.datetime.fromisoformat(created_at_to_db)
            except (ValueError, AttributeError, TypeError) as ve:
                logger.warning(f"无法精确解析 Incus 创建时间 '{original_created_at_to_db}' for {name} 为 ISO 格式 ({ve}). 将尝试使用数据库记录的原值或当前时间.")
                old_db_entry = query_db('SELECT created_at FROM containers WHERE incus_name = ?', [name], one=True)
                if old_db_entry and old_db_entry['created_at']:
                    try:
                        datetime.datetime.fromisoformat(old_db_entry['created_at'])
                        created_at_to_db = old_db_entry['created_at']
                        logger.info(f"使用数据库记录的创建时间 '{created_at_to_db}' for {name}.")
                    except (ValueError, TypeError):
                        logger.warning(f"数据库记录的创建时间 '{old_db_entry['created_at']}' for {name} 也是无效 ISO 格式.")
                        created_at_to_db = datetime.datetime.now().isoformat()
                        logger.info(f"使用当前时间作为创建时间 for {name}.")
                else:
                    created_at_to_db = datetime.datetime.now().isoformat()
                    logger.info(f"使用当前时间作为创建时间 for {name} (Incus did not provide created_at).")
        else:
            old_db_entry = query_db('SELECT created_at FROM containers WHERE incus_name = ?', [name], one=True)
            if old_db_entry and old_db_entry['created_at']:
                try:
                    datetime.datetime.fromisoformat(old_db_entry['created_at'])
                    created_at_to_db = old_db_entry['created_at']
                    logger.info(f"使用数据库记录的创建时间 '{created_at_to_db}' for {name} (Incus did not provide created_at).")
                except (ValueError, TypeError):
                    logger.warning(f"数据库记录的创建时间 '{old_db_entry['created_at']}' for {name} 也是无效 ISO 格式 (Incus did not provide created_at).")
                    created_at_to_db = datetime.datetime.now().isoformat()
                    logger.info(f"使用当前时间作为创建时间 for {name} (Incus did not provide created_at).")
            else:
                created_at_to_db = datetime.datetime.now().isoformat()
                logger.info(f"使用当前时间作为创建时间 for {name} (Incus did not provide created_at).")

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
        logger.error(f"数据库错误 sync_container_to_db for {name}: {e}")
    except Exception as e:
        logger.error(f"sync_container_to_db 中发生未知错误 for {name}: {e}")

def remove_container_from_db(name):
    try:
        query_db('DELETE FROM nat_rules WHERE container_name = ?', [name])
        query_db('DELETE FROM containers WHERE incus_name = ?', [name])
        logger.info(f"从数据库中移除了容器及其NAT规则记录: {name}")
    except sqlite3.Error as e:
         logger.error(f"数据库错误 remove_container_from_db for {name}: {e}")

def check_nat_rule_exists_in_db(container_name, host_port, protocol):
    try:
        rule = query_db('''
            SELECT id FROM nat_rules
            WHERE container_name = ? AND host_port = ? AND protocol = ?
        ''', (container_name, host_port, protocol), one=True)
        return True, rule is not None
    except sqlite3.Error as e:
        logger.error(f"数据库错误 check_nat_rule_exists_in_db for {container_name}, host={host_port}/{protocol}: {e}")
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
        logger.info(f"Added NAT rule to DB: ID {rule_id}, {rule_details['container_name']}, host={rule_details['host_port']}/{rule_details['protocol']}, container={rule_details['ip_at_creation']}:{rule_details['container_port']}")
        return True, rule_id
    except sqlite3.Error as e:
        logger.error(f"数据库错误 add_nat_rule_to_db for {rule_details.get('container_name', 'N/A')}: {e}")
        return False, f"添加规则记录到数据库失败: {e}"

def get_nat_rules_for_container(container_name):
    try:
        rules = query_db('SELECT id, host_port, container_port, protocol, ip_at_creation, created_at FROM nat_rules WHERE container_name = ?', [container_name])
        return True, [dict(row) for row in rules]
    except sqlite3.Error as e:
        logger.error(f"数据库错误 get_nat_rules_for_container for {container_name}: {e}")
        return False, f"从数据库获取规则失败: {e}"

def get_nat_rule_by_id(rule_id):
    try:
        rule = query_db('SELECT id, container_name, host_port, container_port, protocol, ip_at_creation FROM nat_rules WHERE id = ?', [rule_id], one=True)
        return True, dict(rule) if rule else None
    except sqlite3.Error as e:
        logger.error(f"数据库错误 get_nat_rule_by_id for id {rule_id}: {e}")
        return False, f"从数据库获取规则 (ID {rule_id}) 失败: {e}"

def remove_nat_rule_from_db(rule_id):
    try:
        query_db('DELETE FROM nat_rules WHERE id = ?', [rule_id])
        logger.info(f"Removed NAT rule record from DB: ID {rule_id}")
        return True, "规则记录成功从数据库移除。"
    except sqlite3.Error as e:
        logger.error(f"数据库错误 remove_nat_rule_from_db for id {rule_id}: {e}")
        return False, f"从数据库移除规则记录失败: {e}"

def cleanup_orphaned_nat_rules_in_db(existing_incus_container_names):
    try:
        db_rule_container_names_rows = query_db('SELECT DISTINCT container_name FROM nat_rules')
        db_rule_container_names = {row['container_name'] for row in db_rule_container_names_rows}

        orphaned_names = [
            name for name in db_rule_container_names
            if name not in existing_incus_container_names
        ]

        if orphaned_names:
            logger.warning(f"检测到数据库中存在孤立的NAT规则记录，对应的容器已不存在于Incus: {orphaned_names}")
            placeholders = ','.join('?' * len(orphaned_names))
            query_nat = f'DELETE FROM nat_rules WHERE container_name IN ({placeholders})'
            query_db(query_nat, orphaned_names)
            logger.info(f"已从数据库中移除 {len(orphaned_names)} 个孤立容器的NAT规则记录。")

            query_containers = f'DELETE FROM containers WHERE incus_name IN ({placeholders})'
            query_db(query_containers, orphaned_names)
            logger.info(f"已从数据库中移除 {len(orphaned_names)} 个孤立容器记录。")

    except sqlite3.Error as e:
        logger.error(f"数据库错误 cleanup_orphaned_nat_rules_in_db: {e}")
    except Exception as e:
        logger.error(f"清理孤立NAT规则时发生异常: {e}")

def get_quick_commands():
    try:
        commands = query_db('SELECT id, name, command FROM quick_commands ORDER BY name')
        return True, [dict(row) for row in commands]
    except sqlite3.Error as e:
        logger.error(f"数据库错误 get_quick_commands: {e}")
        return False, f"从数据库获取快捷命令失败: {e}"

def add_quick_command(name, command):
    try:
        query_db('INSERT INTO quick_commands (name, command) VALUES (?, ?)', (name, command))
        inserted_row = query_db('SELECT last_insert_rowid()', one=True)
        command_id = inserted_row[0] if inserted_row else None
        logger.info(f"Added quick command to DB: ID {command_id}, Name: {name}")
        return True, command_id
    except sqlite3.IntegrityError:
        logger.warning(f"快捷命令添加失败: 名称 '{name}' 已存在。")
        return False, f"名称为 '{name}' 的快捷命令已存在。"
    except sqlite3.Error as e:
        logger.error(f"数据库错误 add_quick_command for {name}: {e}")
        return False, f"添加快捷命令失败: {e}"

def remove_quick_command_from_db(command_id):
    try:
        query_db('DELETE FROM quick_commands WHERE id = ?', [command_id])
        logger.info(f"Removed quick command record from DB: ID {command_id}")
        return True, "快捷命令记录成功从数据库移除。"
    except sqlite3.Error as e:
        logger.error(f"数据库错误 remove_quick_command_from_db for id {command_id}: {e}")
        return False, f"从数据库移除快捷命令记录失败: {e}"
