import subprocess
import json
import os
import re
import shlex
import sys

_app_logger = None

def init_command_helpers(app):
    global _app_logger
    _app_logger = app.logger

def run_command(command_parts, parse_json=True, timeout=60):
    try:
        env_vars = os.environ.copy()
        env_vars['LC_ALL'] = 'C.UTF-8'
        env_vars['LANG'] = 'C.UTF-8'

        if _app_logger:
             log_command = ' '.join(shlex.quote(part) for part in command_parts)
             _app_logger.info(f"Executing command: {log_command}")

        result = subprocess.run(command_parts, capture_output=True, text=True, check=False, timeout=timeout, env=env_vars)

        if result.returncode != 0:
            error_message = result.stderr.strip() if result.stderr else result.stdout.strip()
            if _app_logger:
                 _app_logger.error(f"Command failed (Exit code {result.returncode}): {log_command if _app_logger else ' '.join(command_parts)}\nError: {error_message}")
            return False, error_message
        else:
             if parse_json:
                 try:
                    output_text = result.stdout.strip()
                    if output_text.startswith(u'\ufeff'):
                        output_text = output_text[1:]
                    return True, json.loads(output_text)
                 except json.JSONDecodeError as e:
                    if _app_logger:
                         _app_logger.error(f"Failed to parse JSON from command output: {result.stdout}\nError: {e}")
                    return False, f"解析命令输出为 JSON 失败: {e}\n原始输出: {result.stdout.strip()}"
             else:
                 return True, result.stdout.strip()

    except FileNotFoundError:
        command_name = command_parts[0] if command_parts else 'command'
        if _app_logger:
             _app_logger.error(f"Command not found: {command_name}. Is it installed and in PATH?")
        return False, f"命令 '{command_name}' 未找到。请确保它已安装并在系统 PATH 中。"
    except subprocess.TimeoutExpired:
        if _app_logger:
             _app_logger.error(f"Command timed out (>{timeout}s): {log_command if _app_logger else ' '.join(command_parts)}")
        return False, f"命令执行超时 (>{timeout}秒)。"
    except Exception as e:
        if _app_logger:
             _app_logger.error(f"执行命令时发生异常: {e}")
        return False, f"执行命令时发生异常: {str(e)}"

def run_incus_command(command_args, parse_json=True, timeout=60):
    return run_command(['incus'] + command_args, parse_json, timeout)

def run_iptables_command(command_args, parse_json=False, timeout=10):
    return run_command(['iptables'] + command_args, parse_json, timeout)
