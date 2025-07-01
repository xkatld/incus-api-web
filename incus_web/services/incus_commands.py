import subprocess
import os
import shlex
import json
import logging
from ..db import query_db

logger = logging.getLogger(__name__)

def run_command(command_parts, parse_json=True, timeout=60):
    try:
        env_vars = os.environ.copy()
        env_vars['LC_ALL'] = 'C.UTF-8'
        result = subprocess.run(command_parts, capture_output=True, text=True, check=False, timeout=timeout, env=env_vars)
        if result.returncode != 0:
            return False, result.stderr.strip() if result.stderr else result.stdout.strip()
        if parse_json:
            try:
                return True, json.loads(result.stdout.strip())
            except json.JSONDecodeError:
                return False, f"解析JSON失败: {result.stdout.strip()}"
        return True, result.stdout.strip()
    except Exception as e:
        return False, str(e)

def run_incus_command(command_args, parse_json=True, timeout=60):
    return run_command(['incus'] + command_args, parse_json, timeout)

def get_container_raw_info(name):
    success_live, live_data = run_incus_command(['list', name, '--format', 'json'])
    if success_live and live_data:
        container_data = live_data[0]
        network = container_data.get('state', {}).get('network', {})
        eth0_addresses = network.get('eth0', {}).get('addresses', [])
        ip_address = next((addr['address'].split('/')[0] for addr in eth0_addresses if addr.get('family') == 'inet' and addr.get('scope') == 'global'), 'N/A')
        info = container_data
        info['ip'] = ip_address
        info['description'] = container_data.get('config', {}).get('image.description', 'N/A')
        return info, None
    db_info = query_db('SELECT * FROM containers WHERE incus_name = ?', [name], one=True)
    if db_info:
        return dict(db_info), '无法从 Incus 获取实时信息，数据来自数据库。'
    return None, f"获取容器 {name} 信息失败。"
