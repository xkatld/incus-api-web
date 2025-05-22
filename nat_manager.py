import shlex
import sqlite3
from . import database
from . import commands

_app_logger = None

def init_nat_manager(app):
    global _app_logger
    _app_logger = app.logger


def check_nat_rule_exists_in_db(container_name, host_port, protocol):
    try:
        rule = database.query_db('''
            SELECT id FROM nat_rules
            WHERE container_name = ? AND host_port = ? AND protocol = ?
        ''', (container_name, host_port, protocol), one=True)
        return True, rule is not None
    except sqlite3.Error as e:
        if _app_logger:
             _app_logger.error(f"Database error check_nat_rule_exists_in_db for {container_name}, host={host_port}/{protocol}: {e}")
        return False, f"检查规则记录失败: {e}"


def add_nat_rule_to_db(rule_details):
    try:
        database.query_db('''
            INSERT INTO nat_rules (container_name, host_port, container_port, protocol, ip_at_creation)
            VALUES (?, ?, ?, ?, ?)
        ''', (rule_details['container_name'], rule_details['host_port'],
              rule_details['container_port'], rule_details['protocol'],
              rule_details['ip_at_creation']))
        inserted_row = database.query_db('SELECT last_insert_rowid()', one=True)
        rule_id = inserted_row[0] if inserted_row else None
        if _app_logger:
            _app_logger.info(f"Added NAT rule to DB: ID {rule_id}, {rule_details['container_name']}, host={rule_details['host_port']}/{rule_details['protocol']}, container={rule_details['ip_at_creation']}:{rule_details['container_port']}")
        return True, rule_id
    except sqlite3.Error as e:
        if _app_logger:
             _app_logger.error(f"Database error add_nat_rule_to_db for {rule_details.get('container_name', 'N/A')}: {e}")
        return False, f"添加规则记录到数据库失败: {e}"

def get_nat_rules_for_container(container_name):
    try:
        rules = database.query_db('SELECT id, host_port, container_port, protocol, ip_at_creation, created_at FROM nat_rules WHERE container_name = ?', [container_name])
        return True, [dict(row) for row in rules]
    except sqlite3.Error as e:
        if _app_logger:
             _app_logger.error(f"Database error get_nat_rules_for_container for {container_name}: {e}")
        return False, f"从数据库获取规则失败: {e}"

def get_nat_rule_by_id(rule_id):
    try:
        rule = database.query_db('SELECT id, container_name, host_port, container_port, protocol, ip_at_creation FROM nat_rules WHERE id = ?', [rule_id], one=True)
        return True, dict(rule) if rule else None
    except sqlite3.Error as e:
        if _app_logger:
             _app_logger.error(f"Database error get_nat_rule_by_id for id {rule_id}: {e}")
        return False, f"从数据库获取规则 (ID {rule_id}) 失败: {e}"


def remove_nat_rule_from_db(rule_id):
    try:
        database.query_db('DELETE FROM nat_rules WHERE id = ?', [rule_id])
        if _app_logger:
             _app_logger.info(f"Removed NAT rule record from DB: ID {rule_id}")
        return True, "规则记录成功从数据库移除。"
    except sqlite3.Error as e:
        if _app_logger:
             _app_logger.error(f"Database error remove_nat_rule_from_db for id {rule_id}: {e}")
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

        if _app_logger:
             _app_logger.info(f"Executing iptables delete for rule ID {rule_details.get('id', 'N/A')}: {' '.join(shlex.quote(part) for part in iptables_command)}")

        success, output = commands.run_iptables_command(iptables_command[1:], parse_json=False)

        if success:
             if _app_logger:
                 _app_logger.info(f"iptables delete successful for rule ID {rule_details.get('id', 'N/A')}.")
             return True, f"成功从 iptables 移除规则 (主机端口 {host_port}/{protocol} 到容器端口 {container_port} @ {ip_at_creation}).", False
        else:
             is_bad_rule = "Bad rule" in output or "No chain/target/match" in output or "No such" in output
             if _app_logger:
                 _app_logger.error(f"iptables delete failed for rule ID {rule_details.get('id', 'N/A')}: {output}. Is Bad Rule: {is_bad_rule}")
             return False, f"从 iptables 移除规则失败 (主机端口 {host_port}/{protocol} 到容器端口 {container_port} @ {ip_at_creation}): {output}", is_bad_rule

    except Exception as e:
        if _app_logger:
             _app_logger.error(f"Exception during perform_iptables_delete_for_rule for rule ID {rule_details.get('id', 'N/A')}: {e}")
        return False, f"执行 iptables 删除命令时发生异常: {str(e)}", False


def cleanup_orphaned_nat_rules_in_db(existing_incus_container_names):
    try:
        db_rule_container_names_rows = database.query_db('SELECT DISTINCT container_name FROM nat_rules')
        db_rule_container_names = {row['container_name'] for row in db_rule_container_names_rows}

        orphaned_names = [
            name for name in db_rule_container_names
            if name not in existing_incus_container_names
        ]

        if orphaned_names:
            if _app_logger:
                _app_logger.warning(f"Detected orphaned NAT rule records in database for containers not present in Incus: {orphaned_names}")
            placeholders = ','.join('?' * len(orphaned_names))
            query = f'DELETE FROM nat_rules WHERE container_name IN ({placeholders})'
            database.query_db(query, orphaned_names)
            if _app_logger:
                 _app_logger.info(f"Removed NAT rule records from database for {len(orphaned_names)} orphaned containers.")
            container_placeholders = ','.join('?' * len(orphaned_names))
            container_query = f'DELETE FROM containers WHERE incus_name IN ({container_placeholders})'
            database.query_db(container_query, orphaned_names)
            if _app_logger:
                 _app_logger.info(f"Removed container records from database for {len(orphaned_names)} orphaned containers (if they existed).")


    except sqlite3.Error as e:
        if _app_logger:
             _app_logger.error(f"Database error cleanup_orphaned_nat_rules_in_db: {e}")
    except Exception as e:
        if _app_logger:
             _app_logger.error(f"Exception while cleaning up orphaned NAT rules: {e}")
