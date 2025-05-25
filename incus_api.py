import logging
import re
from utils import run_incus_command
from db_manager import query_db

logger = logging.getLogger(__name__)

def get_container_raw_info(name):
    db_info = query_db('SELECT * FROM containers WHERE incus_name = ?', [name], one=True)
    success_live, live_data = run_incus_command(['list', name, '--format', 'json'])

    if success_live and isinstance(live_data, list) and len(live_data) > 0 and isinstance(live_data[0], dict):
        container_data = live_data[0]
        info_output = {
            'name': container_data.get('name', name),
            'status': container_data.get('status', '未知'),
            'status_code': container_data.get('status_code', 0),
            'type': container_data.get('type', '未知'),
            'architecture': container_data.get('architecture', 'N/A'),
            'ephemeral': container_data.get('ephemeral', False),
            'created_at': container_data.get('created_at', None),
            'profiles': container_data.get('profiles', []),
            'config': container_data.get('config', {}),
            'devices': container_data.get('devices', {}),
            'snapshots': container_data.get('snapshots', []),
            'state': container_data.get('state', {}),
            'description': container_data.get('config', {}).get('image.description', 'N/A'),
            'ip': 'N/A',
            'live_data_available': True,
            'message': '数据主要来自 Incus 实时信息。',
        }

        container_state = info_output.get('state')
        if isinstance(container_state, dict):
            network_info = container_state.get('network')
            if isinstance(network_info, dict):
                for iface_name, iface_data in network_info.items():
                    if isinstance(iface_data, dict):
                        addresses = iface_data.get('addresses')
                        if isinstance(addresses, list):
                            for addr_entry in addresses:
                                if isinstance(addr_entry, dict):
                                    addr = addr_entry.get('address')
                                    family = addr_entry.get('family')
                                    scope = addr_entry.get('scope')
                                    if addr and family == 'inet' and scope == 'global':
                                        info_output['ip'] = addr.split('/')[0]
                                        break
                            if info_output['ip'] != 'N/A': break
        return info_output, None

    elif db_info:
        info_output = {
            'name': db_info['incus_name'],
            'status': db_info.get('status', '未知'),
            'status_code': 0,
            'type': '容器',
            'architecture': db_info.get('architecture', 'N/A'),
            'ephemeral': False,
            'created_at': db_info.get('created_at', None),
            'profiles': [],
            'config': {},
            'devices': {},
            'snapshots': [],
            'state': {'status': db_info.get('status', '未知'), 'status_code': 0, 'network': {}},
            'description': db_info.get('image_source', 'N/A'),
            'ip': 'N/A',
            'live_data_available': False,
            'message': '无法从 Incus 获取实时信息，数据主要来自数据库快照。',
        }
        return info_output, info_output['message']

    else:
        error_message = f"获取容器 {name} 信息失败: 数据库中无记录且无法从 Incus 获取实时信息。"
        return None, error_message
