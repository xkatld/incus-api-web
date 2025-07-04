import sqlite3
import os
import secrets
import hashlib

DATABASE_NAME = 'incus_manager.db'

DEFAULT_ADMIN_USERNAME = os.environ.get('DEFAULT_ADMIN_USERNAME', 'admin')
DEFAULT_ADMIN_PASSWORD = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'password')
DEFAULT_API_SECRET_KEY = os.environ.get('DEFAULT_API_SECRET_KEY', secrets.token_hex(32))


def create_tables():
    conn = None
    try:
        db_exists = os.path.exists(DATABASE_NAME)
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='containers';")
        if not cursor.fetchone():
            print(f"数据库 {DATABASE_NAME} 不存在或表 'containers' 不存在，正在创建...")
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
            conn.commit()
            print("表 'containers' 创建成功。")
        else:
            print(f"数据库 {DATABASE_NAME} 和表 'containers' 已存在。检查结构...")
            cursor.execute("PRAGMA table_info(containers);")
            containers_columns = [info[1] for info in cursor.fetchall()]
            if 'last_synced' not in containers_columns:
                 print("检测到表 'containers' 缺少列 'last_synced'，正在尝试添加...")
                 try:
                      cursor.execute("ALTER TABLE containers ADD COLUMN last_synced DATETIME DEFAULT CURRENT_TIMESTAMP;")
                      conn.commit()
                      print("'last_synced' 列添加成功。")
                 except sqlite3.Error as e:
                      print(f"错误：添加列 'last_synced' 失败: {e}")
            cursor.execute("PRAGMA index_list(containers);")
            indexes = cursor.fetchall()
            is_unique = False
            for index in indexes:
                if index[2] == 1:
                    cursor.execute(f"PRAGMA index_info('{index[1]}');")
                    index_cols = cursor.fetchall()
                    if len(index_cols) == 1 and index_cols[0][2] == 'incus_name':
                         is_unique = True
                         break
            if not is_unique:
                 print("警告：表 'containers' 的 'incus_name' 列可能没有 UNIQUE 约束。这可能导致同步问题。建议手动检查或重建表。")


        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nat_rules';")
        if not cursor.fetchone():
            print("表 'nat_rules' 不存在，正在创建...")
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
            conn.commit()
            print("表 'nat_rules' 创建成功。")
        else:
            print("表 'nat_rules' 已存在。检查结构...")
            cursor.execute("PRAGMA table_info(nat_rules);")
            nat_columns = [info[1] for info in cursor.fetchall()]
            required_nat_cols = ['container_name', 'host_port', 'container_port', 'protocol', 'ip_at_creation']
            missing_nat_cols = [col for col in required_nat_cols if col not in nat_columns]
            if missing_nat_cols:
                 print(f"检测到表 'nat_rules' 缺少列: {', '.join(missing_nat_cols)}。请手动检查或重建表。")
            if 'ip_at_creation' not in nat_columns:
                 print("检测到表 'nat_rules' 缺少列 'ip_at_creation'，正在尝试添加...")
                 try:
                      cursor.execute("ALTER TABLE nat_rules ADD COLUMN ip_at_creation TEXT;")
                      conn.commit()
                      print("'ip_at_creation' 列添加成功。")
                 except sqlite3.Error as e:
                      print(f"错误：添加列 'ip_at_creation' 失败: {e}")


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
                 print("警告：表 'nat_rules' 可能缺少 UNIQUE (container_name, host_port, protocol) 约束。这可能导致重复规则记录。建议手动检查或重建表。")


        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings';")
        if not cursor.fetchone():
            print("表 'settings' 不存在，正在创建...")
            cursor.execute('''
            CREATE TABLE settings (
                key TEXT UNIQUE NOT NULL,
                value TEXT
            )
            ''')
            conn.commit()
            print("表 'settings' 创建成功。")

        cursor.execute("SELECT COUNT(*) FROM settings;")
        settings_count = cursor.fetchone()[0]

        settings_to_insert = {}

        cursor.execute("SELECT value FROM settings WHERE key = 'admin_username';")
        if not cursor.fetchone():
            settings_to_insert['admin_username'] = DEFAULT_ADMIN_USERNAME
            print(f"设置 'admin_username' 不存在，将使用默认值: {DEFAULT_ADMIN_USERNAME}")

        cursor.execute("SELECT value FROM settings WHERE key = 'admin_password_hash';")
        if not cursor.fetchone():
            password_hash = hashlib.sha256(DEFAULT_ADMIN_PASSWORD.encode('utf-8')).hexdigest()
            settings_to_insert['admin_password_hash'] = password_hash
            print(f"设置 'admin_password_hash' 不存在，将使用默认密码的哈希。默认密码明文: '{DEFAULT_ADMIN_PASSWORD}' -> 哈希: {password_hash}")

        cursor.execute("SELECT value FROM settings WHERE key = 'api_key_hash';")
        if not cursor.fetchone():
            api_hash = hashlib.sha256(DEFAULT_API_SECRET_KEY.encode('utf-8')).hexdigest()
            settings_to_insert['api_key_hash'] = api_hash
            print(f"设置 'api_key_hash' 不存在，将使用默认API密钥的哈希。默认API密钥明文: '{DEFAULT_API_SECRET_KEY}' -> 哈希: {api_hash}")
            print(f"请将此哈希值 ({api_hash}) 用作 API 请求头 'X-API-Key-Hash' 的值。")


        if settings_to_insert:
            print("正在插入/更新默认设置...")
            for key, value in settings_to_insert.items():
                 cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value))
                 cursor.execute("UPDATE settings SET value = ? WHERE key = ?", (value, key))
            conn.commit()
            print(f"{len(settings_to_insert)} 个设置插入/更新完成。")
        else:
            print("所有基本设置键已存在。跳过默认值插入。")

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='quick_commands';")
        if not cursor.fetchone():
            print("表 'quick_commands' 不存在，正在创建...")
            cursor.execute('''
            CREATE TABLE quick_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                command TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            conn.commit()
            print("表 'quick_commands' 创建成功。")
        else:
            print("表 'quick_commands' 已存在。")

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='reverse_proxy_rules';")
        if not cursor.fetchone():
            print("表 'reverse_proxy_rules' 不存在，正在创建...")
            cursor.execute('''
            CREATE TABLE reverse_proxy_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                container_name TEXT NOT NULL,
                domain TEXT UNIQUE NOT NULL,
                container_port INTEGER NOT NULL,
                https_enabled INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            conn.commit()
            print("表 'reverse_proxy_rules' 创建成功。")
        else:
            print("表 'reverse_proxy_rules' 已存在。正在检查 'https_enabled' 列...")
            cursor.execute("PRAGMA table_info(reverse_proxy_rules);")
            columns = [info[1] for info in cursor.fetchall()]
            if 'https_enabled' not in columns:
                print("检测到表 'reverse_proxy_rules' 缺少列 'https_enabled'，正在添加...")
                try:
                    cursor.execute("ALTER TABLE reverse_proxy_rules ADD COLUMN https_enabled INTEGER DEFAULT 0;")
                    conn.commit()
                    print("'https_enabled' 列添加成功。")
                except sqlite3.Error as e:
                    print(f"错误：添加列 'https_enabled' 失败: {e}")
            else:
                print("'https_enabled' 列已存在。")


    except sqlite3.Error as e:
        print(f"数据库错误 during table creation or check: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    create_tables()
    print(f"数据库 '{DATABASE_NAME}' 初始化/检查完成。")