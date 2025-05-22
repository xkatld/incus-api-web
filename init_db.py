import sqlite3
import os
import sys

import config

DATABASE_NAME = config.DATABASE_NAME

def create_tables():
    conn = None
    try:
        db_exists = os.path.exists(DATABASE_NAME)
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='containers';")
        if not cursor.fetchone():
            print(f"Database {DATABASE_NAME} does not exist or table 'containers' does not exist, creating...")
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
            print("Table 'containers' created successfully.")
        else:
            print(f"Database {DATABASE_NAME} and table 'containers' already exist.")
            cursor.execute("PRAGMA table_info(containers);")
            containers_columns = [info[1] for info in cursor.fetchall()]
            if 'last_synced' not in containers_columns:
                 print("Detected missing column 'last_synced' in table 'containers', attempting to add...")
                 try:
                      cursor.execute("ALTER TABLE containers ADD COLUMN last_synced DATETIME DEFAULT CURRENT_TIMESTAMP;")
                      conn.commit()
                      print("'last_synced' column added successfully.")
                 except sqlite3.Error as e:
                      print(f"Error: Failed to add column 'last_synced': {e}")
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
                 print("Warning: 'incus_name' column in table 'containers' may not have a UNIQUE constraint. This might cause sync issues. Consider manual check or recreating the table.")


        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nat_rules';")
        if not cursor.fetchone():
            print("Table 'nat_rules' does not exist, creating...")
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
            print("Table 'nat_rules' created successfully.")
        else:
            print("Table 'nat_rules' already exist.")
            cursor.execute("PRAGMA table_info(nat_rules);")
            nat_columns = [info[1] for info in cursor.fetchall()]
            required_nat_cols = ['container_name', 'host_port', 'container_port', 'protocol', 'ip_at_creation']
            missing_nat_cols = [col for col in required_nat_cols if col not in nat_columns]
            if missing_nat_cols:
                 print(f"Detected missing columns in table 'nat_rules': {', '.join(missing_nat_cols)}. Please manually check or recreate the table.")
            if 'ip_at_creation' not in nat_columns:
                 print("Detected missing column 'ip_at_creation' in table 'nat_rules', attempting to add...")
                 try:
                      cursor.execute("ALTER TABLE nat_rules ADD COLUMN ip_at_creation TEXT;")
                      conn.commit()
                      print("'ip_at_creation' column added successfully.")
                 except sqlite3.Error as e:
                      print(f"Error: Failed to add column 'ip_at_creation': {e}")


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
                 print("Warning: Table 'nat_rules' may be missing the UNIQUE (container_name, host_port, protocol) constraint. This might lead to duplicate rule entries. Consider manual check or recreating the table.")


    except sqlite3.Error as e:
        print(f"Database error during table creation or check: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    create_tables()
    print(f"Database '{DATABASE_NAME}' initialization/check complete.")
