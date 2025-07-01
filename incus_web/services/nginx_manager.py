import os
import logging
from .incus_commands import run_command

logger = logging.getLogger(__name__)
NGINX_SITES_AVAILABLE = '/etc/nginx/sites-available'
NGINX_SITES_ENABLED = '/etc/nginx/sites-enabled'

def get_config_path(domain):
    return os.path.join(NGINX_SITES_AVAILABLE, f'{domain}.conf')

def generate_config(domain, proxy_target_url):
    return f"""server {{
    listen 80;
    server_name {domain};
    location / {{
        proxy_pass {proxy_target_url};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }}
}}"""

def test_and_reload_nginx():
    success_test, out_test = run_command(['sudo', 'nginx', '-t'], parse_json=False)
    if not success_test: return False, out_test
    success_reload, out_reload = run_command(['sudo', 'systemctl', 'reload', 'nginx'], parse_json=False)
    return success_reload, out_reload

def create_reverse_proxy(domain, container_ip, container_port):
    config_path = get_config_path(domain)
    if os.path.exists(config_path): return False, "配置文件已存在。"
    proxy_url = f'http://{container_ip}:{container_port}'
    config_content = generate_config(domain, proxy_url)
    try:
        with open('/tmp/nginx_temp_conf', 'w') as f: f.write(config_content)
        run_command(['sudo', 'mv', '/tmp/nginx_temp_conf', config_path], parse_json=False)
        enabled_path = os.path.join(NGINX_SITES_ENABLED, f'{domain}.conf')
        if not os.path.lexists(enabled_path):
            run_command(['sudo', 'ln', '-s', config_path, enabled_path], parse_json=False)
        return test_and_reload_nginx()
    except Exception as e:
        return False, str(e)

def delete_reverse_proxy(domain):
    config_path = get_config_path(domain)
    if not os.path.exists(config_path): return True, "配置文件未找到。"
    enabled_path = os.path.join(NGINX_SITES_ENABLED, f'{domain}.conf')
    if os.path.lexists(enabled_path):
        run_command(['sudo', 'rm', enabled_path], parse_json=False)
    run_command(['sudo', 'rm', config_path], parse_json=False)
    return test_and_reload_nginx()