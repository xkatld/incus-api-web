import logging
import shlex
from .incus_commands import run_command

logger = logging.getLogger(__name__)

def add_iptables_rule(container_ip, host_port, container_port, protocol):
    iptables_cmd = ['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', protocol, '--dport', str(host_port), '-j', 'DNAT', '--to-destination', f'{container_ip}:{container_port}']
    return run_command(iptables_cmd, parse_json=False)

def perform_iptables_delete_for_rule(rule_details):
    iptables_command = [
        'iptables', '-t', 'nat', '-D', 'PREROUTING',
        '-p', rule_details['protocol'], '--dport', str(rule_details['host_port']),
        '-j', 'DNAT', '--to-destination', f"{rule_details['ip_at_creation']}:{rule_details['container_port']}"
    ]
    success, output = run_command(iptables_command, parse_json=False, timeout=10)
    is_bad_rule = not success and ("Bad rule" in output or "No chain/target/match" in output)
    return success, output, is_bad_rule