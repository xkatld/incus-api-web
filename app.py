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

import config
import database
import commands
import container_manager
import nat_manager
import routes

def create_app():
    app = Flask(__name__)

    database.init_db_helpers(app)
    commands.init_command_helpers(app)
    container_manager.init_container_manager(app)
    nat_manager.init_nat_manager(app)

    app.add_url_rule('/', view_func=routes.index)
    app.add_url_rule('/container/create', view_func=routes.create_container, methods=['POST'])
    app.add_url_rule('/container/<name>/action', view_func=routes.container_action, methods=['POST'])
    app.add_url_rule('/container/<name>/exec', view_func=routes.exec_command, methods=['POST'])
    app.add_url_rule('/container/<name>/info', view_func=routes.container_info)
    app.add_url_rule('/container/<name>/add_nat_rule', view_func=routes.add_nat_rule, methods=['POST'])
    app.add_url_rule('/container/<name>/nat_rules', view_func=routes.list_nat_rules, methods=['GET'])
    app.add_url_rule('/container/nat_rule/<int:rule_id>', view_func=routes.delete_nat_rule, methods=['DELETE'])


    return app

app = create_app()


def check_permissions():
    if os.geteuid() != 0:
        print("警告: 当前用户不是 root。执行 iptables 等命令可能需要 root 权限。")
        print("请考虑使用 'sudo python app.py' 运行此应用 (注意安全性风险)。")
    else:
        print("当前用户是 root。可以执行 iptables 等需要权限的命令。")


def main():
    if not os.path.exists(config.DATABASE_NAME):
        print(f"错误：数据库文件 '{config.DATABASE_NAME}' 未找到。")
        print("请先运行 'python init_db.py' 来初始化数据库。")
        sys.exit(1)

    conn = None
    try:
        conn = database.get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='containers';")
        if not cursor.fetchone():
            print(f"错误：数据库表 'containers' 在 '{config.DATABASE_NAME}' 中未找到。")
            print("请确保 'python init_db.py' 已成功运行并创建了表结构。")
            print("您可以尝试删除旧的 incus_manager.db 文件然后重新运行 init_db.py。")
            sys.exit(1)

        cursor.execute("PRAGMA table_info(containers);")
        containers_columns_info = cursor.fetchall()
        containers_column_names = [col[1] for col in containers_columns_info]
        required_container_columns = ['incus_name', 'status', 'created_at', 'image_source', 'last_synced']
        missing_container_columns = [col for col in required_container_columns if col not in containers_column_names]
        if missing_container_columns:
            print(f"错误：数据库表 'containers' 缺少必需的列: {', '.join(missing_container_columns)}")
            print("请确保 'python init_db.py' 已成功运行并创建了正确的表结构。")
            print("您可以尝试删除旧的 incus_manager.db 文件然后重新运行 init_db.py。")
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
             print("建议删除旧的 incus_manager.db 文件然后重新运行 init_db.py 创建正确的表结构。")


        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nat_rules';")
        if not cursor.fetchone():
             print(f"错误：数据库表 'nat_rules' 在 '{config.DATABASE_NAME}' 中未找到。")
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
            print("您可以尝试删除旧的 incus_manager.db 文件然后重新运行 init_db.py。")
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


    except sqlite3.Error as e:
        print(f"Startup database check error: {e}")
        sys.exit(1)
    finally:
        if conn:
            conn.close()

    try:
        subprocess.run(['incus', '--version'], check=True, capture_output=True, text=True, timeout=10)
        print("Incus command check passed.")
    except FileNotFoundError:
         print("错误：'incus' 命令未找到。请确保 Incus 已正确安装并配置了 PATH。")
         sys.exit(1)
    except subprocess.CalledProcessError as e:
         print(f"错误：执行 'incus --version' 失败 (Exit code {e.returncode}): {e.stderr.strip()}")
         print("请检查 Incus 安装或权限问题。")
         sys.exit(1)
    except subprocess.TimeoutExpired:
         print("错误：执行 'incus --version' 超时。")
         sys.exit(1)
    except Exception as e:
         print(f"Startup Incus check exception: {e}")
         sys.exit(1)

    try:
        subprocess.run(['iptables', '--version'], check=True, capture_output=True, text=True, timeout=5)
        print("iptables command check passed.")
        check_permissions()
    except FileNotFoundError:
         print("警告：'iptables' 命令未找到。NAT 功能可能无法使用。")
    except subprocess.CalledProcessError as e:
         print(f"警告：执行 'iptables --version' failed (Exit code {e.returncode}): {e.stderr.strip()}")
         print("iptables command might have issues or insufficient permissions.")
         check_permissions()
    except subprocess.TimeoutExpired:
         print("警告：执行 'iptables --version' timed out.")
         check_permissions()
    except Exception as e:
         print(f"Startup iptables check exception: {e}")
         check_permissions()


    print("Starting Flask Web Server...")
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()
