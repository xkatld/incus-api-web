import subprocess
import logging

logger = logging.getLogger(__name__)

def run_iptables_command(command):
    try:
        result = subprocess.run(
            ['sudo'] + command,
            capture_output=True,
            text=True,
            check=True,
            timeout=30
        )
        return True, result.stdout.strip()
    except FileNotFoundError:
        return False, "sudo 或 iptables 命令未找到"
    except subprocess.CalledProcessError as e:
        logger.error(f"执行 iptables 命令失败: {e.stderr}")
        return False, e.stderr
    except Exception as e:
        logger.error(f"执行 iptables 命令时发生错误: {e}")
        return False, str(e)

def add_iptables_rule(container_ip, host_port, container_port, protocol):
    try:
        host_p = int(host_port)
        container_p = int(container_port)
        if not (1 <= host_p <= 65535 and 1 <= container_p <= 65535):
            raise ValueError("端口号超出有效范围")
    except ValueError:
        return False, "无效的端口号。请输入1-65535之间的数字。"

    protocol = protocol.lower()
    if protocol not in ['tcp', 'udp']:
        return False, "无效的协议，请使用 'tcp' 或 'udp'。"

    commands = [
        ['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', protocol, '--dport', str(host_p), '-j', 'DNAT', '--to-destination', f"{container_ip}:{container_p}"],
        ['iptables', '-t', 'filter', '-A', 'FORWARD', '-p', protocol, '-d', container_ip, '--dport', str(container_p), '-j', 'ACCEPT']
    ]

    for cmd in commands:
        success, output = run_iptables_command(cmd)
        if not success:
            return False, output
    return True, "规则添加成功"

def perform_iptables_delete_for_rule(rule):
    try:
        host_p = int(rule['host_port'])
        container_p = int(rule['container_port'])
        if not (1 <= host_p <= 65535 and 1 <= container_p <= 65535):
            raise ValueError("端口号超出有效范围")
        container_ip = rule.get('ip_at_creation')
        if not container_ip:
            return False, "规则中缺少容器IP地址", True
    except (ValueError, KeyError):
        return False, "规则数据无效或不完整", True

    protocol = rule.get('protocol', 'tcp').lower()
    commands = [
        ['iptables', '-t', 'nat', '-D', 'PREROUTING', '-p', protocol, '--dport', str(host_p), '-j', 'DNAT', '--to-destination', f"{container_ip}:{container_p}"],
        ['iptables', '-t', 'filter', '-D', 'FORWARD', '-p', protocol, '-d', container_ip, '--dport', str(container_p), '-j', 'ACCEPT']
    ]

    all_good = True
    output_details = []
    is_bad_rule_in_db = False

    for cmd in commands:
        success, output = run_iptables_command(cmd)
        if not success:
            all_good = False
            output_details.append(output)
            if "No chain/target/match by that name" in output:
                is_bad_rule_in_db = True

    return all_good, " ".join(output_details), is_bad_rule_in_db