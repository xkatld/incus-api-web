import sqlite3
import logging
import datetime
import re
import os
from flask import current_app, g

logger = logging.getLogger(__name__)

def get_db():
    if 'db' not in g:
        db_path = os.path.join(current_app.instance_path, current_app.config['DATABASE_NAME'])
        if not os.path.exists(db_path):
            raise sqlite3.OperationalError(f"数据库文件不存在: {db_path}")
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(query, args)
        if query.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE')):
            db.commit()
        rv = cur.fetchall()
    except sqlite3.Error as e:
        logger.error(f"数据库查询错误: {e}\nQuery: {query}\nArgs: {args}")
        rv = []
        db.rollback()
    return (rv[0] if rv else None) if one else rv

def load_settings_from_db():
    try:
        settings_rows = query_db('SELECT key, value FROM settings')
        if not settings_rows:
            return None
        return {row['key']: row['value'] for row in settings_rows}
    except sqlite3.OperationalError:
        return None
    except Exception as e:
        logger.error(f"加载设置时发生异常: {e}")
        return None

def sync_container_to_db(name, image_source, status, created_at_str):
    created_at_to_db = str(created_at_str) if created_at_str is not None else None
    if created_at_to_db:
        try:
            datetime.datetime.fromisoformat(created_at_to_db.replace('Z', '+00:00'))
        except (ValueError, TypeError):
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

def remove_container_from_db(name):
    query_db('DELETE FROM nat_rules WHERE container_name = ?', [name])
    query_db('DELETE FROM containers WHERE incus_name = ?', [name])

def check_nat_rule_exists_in_db(container_name, host_port, protocol):
    rule = query_db('SELECT id FROM nat_rules WHERE container_name = ? AND host_port = ? AND protocol = ?', (container_name, host_port, protocol), one=True)
    return True, rule is not None

def add_nat_rule_to_db(rule_details):
    res = query_db('''
        INSERT INTO nat_rules (container_name, host_port, container_port, protocol, ip_at_creation)
        VALUES (?, ?, ?, ?, ?)
    ''', (rule_details['container_name'], rule_details['host_port'], rule_details['container_port'], rule_details['protocol'], rule_details['ip_at_creation']))
    inserted_row = query_db('SELECT last_insert_rowid()', one=True)
    return True, inserted_row[0] if inserted_row else None

def get_nat_rules_for_container(container_name):
    rules = query_db('SELECT id, host_port, container_port, protocol, ip_at_creation, created_at FROM nat_rules WHERE container_name = ?', [container_name])
    return True, [dict(row) for row in rules]

def get_nat_rule_by_id(rule_id):
    rule = query_db('SELECT id, container_name, host_port, container_port, protocol, ip_at_creation FROM nat_rules WHERE id = ?', [rule_id], one=True)
    return True, dict(rule) if rule else None

def remove_nat_rule_from_db(rule_id):
    query_db('DELETE FROM nat_rules WHERE id = ?', [rule_id])
    return True, "规则记录成功从数据库移除。"

def get_quick_commands():
    commands = query_db('SELECT id, name, command FROM quick_commands ORDER BY name')
    return True, [dict(row) for row in commands]

def add_quick_command(name, command):
    try:
        query_db('INSERT INTO quick_commands (name, command) VALUES (?, ?)', (name, command))
        inserted_row = query_db('SELECT last_insert_rowid()', one=True)
        return True, inserted_row[0] if inserted_row else None
    except sqlite3.IntegrityError:
        return False, f"名称为 '{name}' 的快捷命令已存在。"

def remove_quick_command_from_db(command_id):
    query_db('DELETE FROM quick_commands WHERE id = ?', [command_id])
    return True, "快捷命令记录成功从数据库移除。"

def add_reverse_proxy_rule_to_db(container_name, domain, container_port):
    try:
        query_db('INSERT INTO reverse_proxy_rules (container_name, domain, container_port) VALUES (?, ?, ?)', (container_name, domain, container_port))
        inserted_row = query_db('SELECT last_insert_rowid()', one=True)
        return True, inserted_row[0] if inserted_row else None
    except sqlite3.IntegrityError:
        return False, f"域名 '{domain}' 已存在。"

def get_reverse_proxy_rules_for_container(container_name):
    rules = query_db('SELECT id, domain, container_port, created_at FROM reverse_proxy_rules WHERE container_name = ?', [container_name])
    return True, [dict(row) for row in rules]

def get_reverse_proxy_rule_by_id(rule_id):
    rule = query_db('SELECT id, container_name, domain, container_port FROM reverse_proxy_rules WHERE id = ?', [rule_id], one=True)
    return True, dict(rule) if rule else None

def remove_reverse_proxy_rule_from_db(rule_id):
    query_db('DELETE FROM reverse_proxy_rules WHERE id = ?', [rule_id])
    return True, "规则记录成功从数据库移除。"

def init_app(app):
    app.config.setdefault('DATABASE_NAME', 'incus_manager.db')
    app.teardown_appcontext(close_db)