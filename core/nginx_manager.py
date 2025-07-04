import os
import logging
from .utils import run_command

logger = logging.getLogger(__name__)

NGINX_SITES_AVAILABLE = '/etc/nginx/sites-available'
NGINX_SITES_ENABLED = '/etc/nginx/sites-enabled'

def get_nginx_config_path(domain):
    return os.path.join(NGINX_SITES_AVAILABLE, f'{domain}.conf')

def generate_nginx_config(domain, proxy_target_url, https_enabled=False):
    if not https_enabled:
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
    else:
        ssl_certificate_path = f'/etc/letsencrypt/live/{domain}/fullchain.pem'
        ssl_key_path = f'/etc/letsencrypt/live/{domain}/privkey.pem'
        return f"""
server {{
    listen 80;
    server_name {domain};

    # Redirect all HTTP requests to HTTPS
    location / {{
        return 301 https://$host$request_uri;
    }}
}}

server {{
    listen 443 ssl http2;
    server_name {domain};

    ssl_certificate {ssl_certificate_path};
    ssl_certificate_key {ssl_key_path};

    # SSL parameters
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
    ssl_ecdh_curve secp384r1;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;

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
    if not success and ("test is successful" not in output and "syntax is ok" not in output):
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

def obtain_certificate(domain):
    """
    使用 Certbot (Nginx 插件) 自动获取证书。
    这是一个模拟过程，实际使用需要安装 Certbot: sudo apt install certbot python3-certbot-nginx
    """
    logger.info(f"正在为域名 {domain} 尝试获取 SSL 证书...")
    # --nginx: 使用 nginx 插件自动配置
    # -d: 指定域名
    # --non-interactive: 非交互模式
    # --agree-tos: 同意服务条款
    # -m: 紧急通知邮箱 (这里使用示例)
    # --redirect: 自动将 HTTP 重定向到 HTTPS (我们自己模板里也做了)
    certbot_command = [
        'sudo', 'certbot', '--nginx', '-d', domain,
        '--non-interactive', '--agree-tos', '-m', f'admin@{domain}',
        '--redirect'
    ]
    success, output = run_command(certbot_command, parse_json=False, timeout=300)
    if not success:
        logger.error(f"Certbot 获取证书失败 for {domain}: {output}")
        return False, f"获取 SSL 证书失败: {output}"
    
    logger.info(f"成功为 {domain} 获取或续订了证书。")
    return True, "SSL 证书获取成功。"


def create_reverse_proxy(domain, container_ip, container_port, https_enabled=False):
    config_path = get_nginx_config_path(domain)
    if os.path.exists(config_path):
        return False, f"配置文件 {config_path} 已存在。"

    proxy_url = f'http://{container_ip}:{container_port}'
    
    # 如果启用 HTTPS，则先生成一个临时的 HTTP 配置以供 Certbot 验证
    temp_config_for_certbot = generate_nginx_config(domain, proxy_url, https_enabled=False)

    try:
        with open('/tmp/nginx_temp_conf', 'w') as f:
            f.write(temp_config_for_certbot)
        
        success_mv, out_mv = run_command(['sudo', 'mv', '/tmp/nginx_temp_conf', config_path], parse_json=False)
        if not success_mv:
            return False, f"无法创建 Nginx 配置文件: {out_mv}"

        enabled_path = os.path.join(NGINX_SITES_ENABLED, f'{domain}.conf')
        if not os.path.lexists(enabled_path):
             success_ln, out_ln = run_command(['sudo', 'ln', '-s', config_path, enabled_path], parse_json=False)
             if not success_ln:
                  run_command(['sudo', 'rm', config_path], parse_json=False) # 清理
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
            return False, msg_reload
        
        # 如果启用 HTTPS，现在运行 Certbot
        if https_enabled:
            cert_success, cert_msg = obtain_certificate(domain)
            if not cert_success:
                # 如果证书获取失败，回滚 Nginx 配置
                delete_reverse_proxy(domain)
                return False, f"证书获取失败，反向代理配置已回滚。原因: {cert_msg}"
            
            # Certbot 会自动修改 Nginx 配置并重载，理论上不需要我们再做什么
            # 但为了保险，我们可以重新生成我们的标准配置并重载
            final_config_content = generate_nginx_config(domain, proxy_url, https_enabled=True)
            with open('/tmp/nginx_temp_conf_ssl', 'w') as f:
                f.write(final_config_content)
            
            run_command(['sudo', 'mv', '/tmp/nginx_temp_conf_ssl', config_path], parse_json=False)
            test_nginx_config()
            reload_nginx()

        return True, "反向代理创建成功。"

    except Exception as e:
        logger.error(f"创建反向代理时发生异常: {e}")
        # 尝试清理
        if 'enabled_path' in locals() and os.path.lexists(enabled_path):
            run_command(['sudo', 'rm', enabled_path], parse_json=False)
        if os.path.exists(config_path):
            run_command(['sudo', 'rm', config_path], parse_json=False)
        
        return False, f"创建反向代理时发生异常: {e}"

def delete_reverse_proxy(domain, https_enabled=False):
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
            # 如果主配置文件删除失败，尝试恢复软链接
            if not os.path.lexists(enabled_path):
                run_command(['sudo', 'ln', '-s', config_path, enabled_path], parse_json=False)
            return False, f"删除配置文件失败: {out_rm}"
        
        # 如果是 HTTPS，尝试删除证书
        if https_enabled:
            logger.info(f"正在为 {domain} 删除 SSL 证书...")
            # Certbot delete 命令会移除所有与该证书相关的配置，并删除证书
            certbot_delete_cmd = ['sudo', 'certbot', 'delete', '--non-interactive', '--cert-name', domain]
            del_cert_success, del_cert_out = run_command(certbot_delete_cmd, parse_json=False, timeout=120)
            if not del_cert_success:
                logger.warning(f"删除 {domain} 的证书失败: {del_cert_out}。可能需要手动清理。")


        success_test, msg_test = test_nginx_config()
        if not success_test:
            # 尝试恢复配置
            # 注意：这里简化了恢复逻辑，实际情况可能更复杂
            return False, f"删除配置后 Nginx 测试失败: {msg_test}。可能需要手动干预。"
        
        success_reload, msg_reload = reload_nginx()
        if not success_reload:
            return False, f"重载 Nginx 失败: {msg_reload}"

        return True, "反向代理删除成功。"

    except Exception as e:
        logger.error(f"删除反向代理时发生异常: {e}")
        return False, f"删除反向代理时发生异常: {e}"