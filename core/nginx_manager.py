import os
import logging
from .utils import run_command

logger = logging.getLogger(__name__)

NGINX_SITES_AVAILABLE = '/etc/nginx/sites-available'
NGINX_SITES_ENABLED = '/etc/nginx/sites-enabled'

def get_nginx_config_path(domain):
    return os.path.join(NGINX_SITES_AVAILABLE, f'{domain}.conf')

def generate_nginx_config(domain, proxy_target_url):
    return f"""
server {{
    listen 80;
    server_name {domain};

    location / {{
        proxy_pass {proxy_target_url};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"""

def test_nginx_config():
    success, output = run_command(['sudo', 'nginx', '-t'], parse_json=False)
    if not success and "test is successful" not in output:
        logger.error(f"Nginx 配置测试失败: {output}")
        return False, f"Nginx 配置测试失败: {output}"
    logger.info("Nginx 配置测试成功。")
    return True, "Nginx 配置测试成功。"

def reload_nginx():
    success, output = run_command(['sudo', 'systemctl', 'reload', 'nginx'], parse_json=False)
    if not success:
        logger.error(f"重载 Nginx 失败: {output}")
        return False, f"重载 Nginx 失败: {output}"
    logger.info("Nginx 重载成功。")
    return True, "Nginx 重载成功。"

def create_reverse_proxy(domain, container_ip, container_port):
    config_path = get_nginx_config_path(domain)
    if os.path.exists(config_path):
        return False, f"配置文件 {config_path} 已存在。"

    proxy_url = f'http://{container_ip}:{container_port}'
    config_content = generate_nginx_config(domain, proxy_url)

    try:
        with open('/tmp/nginx_temp_conf', 'w') as f:
            f.write(config_content)
        
        success_mv, out_mv = run_command(['sudo', 'mv', '/tmp/nginx_temp_conf', config_path], parse_json=False)
        if not success_mv:
            return False, f"无法创建 Nginx 配置文件: {out_mv}"

        enabled_path = os.path.join(NGINX_SITES_ENABLED, f'{domain}.conf')
        if not os.path.lexists(enabled_path):
             success_ln, out_ln = run_command(['sudo', 'ln', '-s', config_path, enabled_path], parse_json=False)
             if not success_ln:
                  run_command(['sudo', 'rm', config_path], parse_json=False)
                  return False, f"无法启用 Nginx 站点: {out_ln}"

        success_test, msg_test = test_nginx_config()
        if not success_test:
            run_command(['sudo', 'rm', enabled_path], parse_json=False)
            run_command(['sudo', 'rm', config_path], parse_json=False)
            return False, msg_test

        success_reload, msg_reload = reload_nginx()
        if not success_reload:
            run_command(['sudo', 'rm', enabled_path], parse_json=False)
            run_command(['sudo', 'rm', config_path], parse_json=False)
            test_nginx_config()
            reload_nginx()
            return False, msg_reload
            
        return True, "反向代理创建成功。"

    except Exception as e:
        logger.error(f"创建反向代理时发生异常: {e}")
        return False, f"创建反向代理时发生异常: {e}"

def delete_reverse_proxy(domain):
    config_path = get_nginx_config_path(domain)
    enabled_path = os.path.join(NGINX_SITES_ENABLED, f'{domain}.conf')

    if not os.path.exists(config_path):
        return False, "配置文件未找到，可能已被手动删除。"

    try:
        if os.path.lexists(enabled_path):
            success_rm_ln, out_rm_ln = run_command(['sudo', 'rm', enabled_path], parse_json=False)
            if not success_rm_ln:
                return False, f"删除符号链接失败: {out_rm_ln}"
        
        success_rm, out_rm = run_command(['sudo', 'rm', config_path], parse_json=False)
        if not success_rm:
            return False, f"删除配置文件失败: {out_rm}"

        success_test, msg_test = test_nginx_config()
        if not success_test:
            return False, f"删除配置后 Nginx 测试失败: {msg_test}"
        
        success_reload, msg_reload = reload_nginx()
        if not success_reload:
            return False, f"重载 Nginx 失败: {msg_reload}"

        return True, "反向代理删除成功。"

    except Exception as e:
        logger.error(f"删除反向代理时发生异常: {e}")
        return False, f"删除反向代理时发生异常: {e}"