# init_db.py
import sqlite3
import os

DATABASE_NAME = 'incus_manager.db'

def create_tables():
    """创建数据库表"""
    # 检查数据库文件是否存在，如果存在则不重复创建
    db_exists = os.path.exists(DATABASE_NAME)

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    if not db_exists:
        print(f"数据库 {DATABASE_NAME} 不存在，正在创建...")
        # 创建容器信息表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS containers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incus_name TEXT UNIQUE NOT NULL,
            image_source TEXT,
            status TEXT,
            created_at TEXT, 
            last_synced DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        # 可以添加其他表，例如操作日志等
        print("表 'containers' 创建成功。")
    else:
        # 检查 'containers' 表是否存在，如果不存在则创建
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='containers';")
        if not cursor.fetchone():
            print("表 'containers' 不存在，正在创建...")
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS containers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incus_name TEXT UNIQUE NOT NULL,
                image_source TEXT,
                status TEXT,
                created_at TEXT, 
                last_synced DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            print("表 'containers' 创建成功。")
        else:
            print(f"数据库 {DATABASE_NAME} 和表 'containers' 已存在。")


    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_tables()
    print(f"数据库 '{DATABASE_NAME}' 初始化完成。")
