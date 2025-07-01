import os
import subprocess
import logging

logger = logging.getLogger(__name__)

NGINX_SITES_AVAILABLE = '/etc/nginx/sites-available'
NGINX_SITES_ENABLED = '/etc/nginx/sites-enabled'

def is_valid_domain_for_filename(domain):
    if '/' in domain or '\\' in domain or '..' in domain:
        return False
    return True

def run_command(command, check=True):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=check,
            timeout=30
        )
        return True, result.stdout.strip()
    except FileNotFoundError:
        logger.error(f"命令未找到: {command[0]}")
        return False, f"命令未找到: {command[0]}"
    except subprocess.CalledProcessError as e:
        logger.error(f"执行命令失败: {command}. 错误: {e.stderr}")
        return False, e.stderr
    except subprocess.TimeoutExpired:
        logger.error(f"执行命令超时: {command}")
        return False, "命令执行超时"
    except Exception as e:
        logger.error(f"执行命令时发生未知错误: {command}. 错误: {e}")
        return False, str(e)

def create_reverse_proxy(domain, container_ip, container_port):
    if not is_valid_domain_for_filename(domain):
        return False, "域名包含无效字符，无法创建配置文件。"

    config_path = os.path.join(NGINX_SITES_AVAILABLE, domain)
    if os.path.exists(config_path):
        return False, "该域名的配置文件已存在。"

    config_content = f"""
server {{
    listen 80;
    server_name {domain};

    location / {{
        proxy_pass http://{container_ip}:{container_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"""
    try:
        with open(config_path, 'w') as f:
            f.write(config_content)
    except IOError as e:
        return False, f"写入Nginx配置文件失败: {e}"

    enabled_path = os.path.join(NGINX_SITES_ENABLED, domain)
    if not os.path.lexists(enabled_path):
        os.symlink(config_path, enabled_path)

    return run_command(['sudo', 'nginx', '-t']) and run_command(['sudo', 'systemctl', 'reload', 'nginx'])

def delete_reverse_proxy(domain):
    if not is_valid_domain_for_filename(domain):
        return False, "域名包含无效字符。"

    config_path = os.path.join(NGINX_SITES_AVAILABLE, domain)
    enabled_path = os.path.join(NGINX_SITES_ENABLED, domain)

    if os.path.exists(enabled_path):
        os.remove(enabled_path)
    if os.path.exists(config_path):
        os.remove(config_path)

    return run_command(['sudo', 'nginx', '-t']) and run_command(['sudo', 'systemctl', 'reload', 'nginx'])