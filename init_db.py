import sqlite3
import os

DATABASE_NAME = 'incus_manager.db'

def create_tables():
    """创建或检查数据库表"""
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
                incus_name TEXT UNIQUE NOT NULL, -- UNIQUE constraint is important for upserts
                image_source TEXT,
                status TEXT,
                created_at TEXT,
                last_synced DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            conn.commit()
            print("表 'containers' 创建成功。")
        else:
            print(f"数据库 {DATABASE_NAME} 和表 'containers' 已存在。")
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
                ip_at_creation TEXT NOT NULL, -- Store the container IP when the rule was added
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (container_name, host_port, protocol) -- Prevent duplicate rules for the same host port/protocol
            )
            ''')
            conn.commit()
            print("表 'nat_rules' 创建成功。")
        else:
            print("表 'nat_rules' 已存在。")
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


    except sqlite3.Error as e:
        print(f"数据库错误 during table creation or check: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    create_tables()
    print(f"数据库 '{DATABASE_NAME}' 初始化/检查完成。")
