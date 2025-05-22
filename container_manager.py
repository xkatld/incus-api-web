import datetime
import re
import sqlite3
from . import database
from . import commands

_app_logger = None

def init_container_manager(app):
    global _app_logger
    _app_logger = app.logger

def sync_container_to_db(name, image_source, status, created_at_str):
    try:
        created_at_to_db = str(created_at_str) if created_at_str is not None else None

        if created_at_to_db:
            original_created_at_to_db = created_at_to_db
            try:
                if created_at_to_db.endswith('Z'):
                   created_at_to_db = created_at_to_db[:-1] + '+00:00'

                tz_match_hhmm = re.search(r'([+-])(\d{4})$', created_at_to_db)
                if tz_match_hhmm:
                    sign = tz_match_hhmm.group(1)
                    hhmm = tz_match_hhmm.group(2)
                    created_at_to_db = created_at_to_db[:-4] + f"{sign}{hhmm[:2]}:{hhmm[2:]}"

                parts = created_at_to_db.split('.')
                if len(parts) > 1:
                    time_tz_part = parts[1]
                    tz_start_match = re.search(r'[+-]\d', time_tz_part)
                    if tz_start_match:
                         micro_part = time_tz_part[:tz_start_match.start()]
                         tz_part = time_tz_part[tz_start_match.start():]
                         if len(micro_part) > 6:
                            micro_part = micro_part[:6]
                         time_tz_part = micro_part + tz_part
                    else:
                        if len(time_tz_part) > 6:
                            time_tz_part = time_tz_part[:6]

                    created_at_to_db = parts[0] + '.' + time_tz_part
                elif re.search(r'[+-]\d{2}:?\d{2}$', created_at_to_db):
                     time_segment = created_at_to_db.split('T')[-1]
                     if '.' not in time_segment.split(re.search(r'[+-]', time_segment).group(0))[0]:
                           tz_part = re.search(r'[+-]\d{2}:?\d{2}$', created_at_to_db).group(0)
                           if '.' not in created_at_to_db:
                              created_at_to_db = created_at_to_db.replace(tz_part, '.000000' + tz_part)


                datetime.datetime.fromisoformat(created_at_to_db)

            except (ValueError, AttributeError, TypeError) as ve:
                if _app_logger:
                     _app_logger.warning(f"Unable to parse Incus creation time '{original_created_at_to_db}' for {name} to ISO format ({ve}). Will try using database record or current time.")
                old_db_entry = database.query_db('SELECT created_at FROM containers WHERE incus_name = ?', [name], one=True)
                if old_db_entry and old_db_entry['created_at']:
                     try:
                          datetime.datetime.fromisoformat(old_db_entry['created_at'])
                          created_at_to_db = old_db_entry['created_at']
                          if _app_logger:
                             _app_logger.info(f"Using database recorded created_at '{created_at_to_db}' for {name}.")
                     except (ValueError, TypeError):
                          if _app_logger:
                             _app_logger.warning(f"Database recorded created_at '{old_db_entry['created_at']}' for {name} is also invalid ISO format.")
                          created_at_to_db = datetime.datetime.now().isoformat()
                          if _app_logger:
                             _app_logger.info(f"Using current time as created_at for {name}.")
                else:
                     created_at_to_db = datetime.datetime.now().isoformat()
                     if _app_logger:
                         _app_logger.info(f"Using current time as created_at for {name} (Incus did not provide created_at).")

        else:
             old_db_entry = database.query_db('SELECT created_at FROM containers WHERE incus_name = ?', [name], one=True)
             if old_db_entry and old_db_entry['created_at']:
                 try:
                      datetime.datetime.fromisoformat(old_db_entry['created_at'])
                      created_at_to_db = old_db_entry['created_at']
                      if _app_logger:
                          _app_logger.info(f"Using database recorded created_at '{created_at_to_db}' for {name} (Incus did not provide created_at).")
                 except (ValueError, TypeError):
                      if _app_logger:
                         _app_logger.warning(f"Database recorded created_at '{old_db_entry['created_at']}' for {name} is also invalid ISO format (Incus did not provide created_at).")
                      created_at_to_db = datetime.datetime.now().isoformat()
                      if _app_logger:
                          _app_logger.info(f"Using current time as created_at for {name} (Incus did not provide created_at).")
             else:
                  created_at_to_db = datetime.datetime.now().isoformat()
                  if _app_logger:
                     _app_logger.info(f"Using current time as created_at for {name} (Incus did not provide created_at).")


        database.query_db('''
            INSERT INTO containers (incus_name, image_source, status, created_at, last_synced)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(incus_name) DO UPDATE SET
                image_source = excluded.image_source,
                status = excluded.status,
                created_at = excluded.created_at,
                last_synced = CURRENT_TIMESTAMP
        ''', (name, image_source, status, created_at_to_db))
    except sqlite3.Error as e:
        if _app_logger:
             _app_logger.error(f"Database error sync_container_to_db for {name}: {e}")


def remove_container_from_db(name):
    try:
        database.query_db('DELETE FROM containers WHERE incus_name = ?', [name])
        if _app_logger:
             _app_logger.info(f"Removed container record from database: {name}")
    except sqlite3.Error as e:
         if _app_logger:
             _app_logger.error(f"Database error remove_container_from_db for {name}: {e}")

def get_container_raw_info(name):
    db_info = database.query_db('SELECT * FROM containers WHERE incus_name = ?', [name], one=True)
    success_live, live_data = commands.run_incus_command(['list', name, '--format', 'json'])

    if success_live and isinstance(live_data, list) and len(live_data) > 0 and isinstance(live_data[0], dict):
        container_data = live_data[0]
        info_output = {
            'name': container_data.get('name', name),
            'status': container_data.get('status', 'Unknown'),
            'status_code': container_data.get('status_code', 0),
            'type': container_data.get('type', 'unknown'),
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
            'status': db_info.get('status', 'Unknown'),
            'status_code': 0,
            'type': 'container',
            'architecture': db_info.get('architecture', 'N/A'),
            'ephemeral': False,
            'created_at': db_info.get('created_at', None),
            'profiles': [],
            'config': {},
            'devices': {},
            'snapshots': [],
             'state': {'status': db_info.get('status', 'Unknown'), 'status_code': 0, 'network': {}},
            'description': db_info.get('image_source', 'N/A'),
            'ip': 'N/A',
            'live_data_available': False,
            'message': '无法从 Incus 获取实时信息，数据主要来自数据库快照。',
        }
        return info_output, info_output['message']

    else:
        error_message = f"获取容器 {name} 信息失败: 数据库中无记录且无法从 Incus 获取实时信息。"
        return None, error_message
