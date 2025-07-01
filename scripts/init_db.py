import sqlite3
import os
import sys
import secrets
import hashlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from incus_web.config import DATABASE_NAME

INSTANCE_FOLDER_PATH = os.path.join(os.path.dirname(__file__), '..', 'instance')
DATABASE_PATH = os.path.join(INSTANCE_FOLDER_PATH, DATABASE_NAME)
DEFAULT_ADMIN_USERNAME = os.environ.get('DEFAULT_ADMIN_USERNAME', 'admin')
DEFAULT_ADMIN_PASSWORD = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'password')
DEFAULT_API_SECRET_KEY = os.environ.get('DEFAULT_API_SECRET_KEY', secrets.token_hex(32))

def create_tables():
    if not os.path.exists(INSTANCE_FOLDER_PATH):
        os.makedirs(INSTANCE_FOLDER_PATH)
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='containers';")
        if not cursor.fetchone():
            cursor.execute('''
            CREATE TABLE containers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incus_name TEXT UNIQUE NOT NULL,
                image_source TEXT,
                status TEXT,
                created_at TEXT,
                last_synced DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            ''')
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nat_rules';")
        if not cursor.fetchone():
            cursor.execute('''
            CREATE TABLE nat_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                container_name TEXT NOT NULL,
                host_port INTEGER NOT NULL,
                container_port INTEGER NOT NULL,
                protocol TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp')),
                ip_at_creation TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (container_name, host_port, protocol)
            )
            ''')
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings';")
        if not cursor.fetchone():
            cursor.execute('''
            CREATE TABLE settings (
                key TEXT UNIQUE NOT NULL,
                value TEXT
            )
            ''')
        settings_to_insert = {}
        cursor.execute("SELECT value FROM settings WHERE key = 'admin_username';")
        if not cursor.fetchone():
            settings_to_insert['admin_username'] = DEFAULT_ADMIN_USERNAME
        cursor.execute("SELECT value FROM settings WHERE key = 'admin_password_hash';")
        if not cursor.fetchone():
            password_hash = hashlib.sha256(DEFAULT_ADMIN_PASSWORD.encode('utf-8')).hexdigest()
            settings_to_insert['admin_password_hash'] = password_hash
        cursor.execute("SELECT value FROM settings WHERE key = 'api_key_hash';")
        if not cursor.fetchone():
            api_hash = hashlib.sha256(DEFAULT_API_SECRET_KEY.encode('utf-8')).hexdigest()
            settings_to_insert['api_key_hash'] = api_hash
        if settings_to_insert:
            for key, value in settings_to_insert.items():
                 cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value))
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='quick_commands';")
        if not cursor.fetchone():
            cursor.execute('''
            CREATE TABLE quick_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                command TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            ''')
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='reverse_proxy_rules';")
        if not cursor.fetchone():
            cursor.execute('''
            CREATE TABLE reverse_proxy_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                container_name TEXT NOT NULL,
                domain TEXT UNIQUE NOT NULL,
                container_port INTEGER NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            ''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"数据库错误: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    create_tables()
    print(f"数据库 '{DATABASE_NAME}' 初始化/检查完成。")