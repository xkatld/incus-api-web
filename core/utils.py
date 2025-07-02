import subprocess
import os
import shlex
import json
import logging

logger = logging.getLogger(__name__)

def run_command(command_parts, parse_json=True, timeout=60):
    try:
        env_vars = os.environ.copy()
        env_vars['LC_ALL'] = 'C.UTF-8'
        env_vars['LANG'] = 'C.UTF-8'

        log_command = ' '.join(shlex.quote(part) for part in command_parts)
        logger.info(f"执行命令: {log_command}")

        result = subprocess.run(command_parts, capture_output=True, text=True, check=False, timeout=timeout, env=env_vars)

        if result.returncode != 0:
            error_message = result.stderr.strip() if result.stderr else result.stdout.strip()
            logger.error(f"命令失败 (退出码 {result.returncode}): {log_command}\n错误: {error_message}")
            return False, error_message
        else:
            if parse_json:
                try:
                    output_text = result.stdout.strip()
                    if output_text.startswith(u'\ufeff'):
                        output_text = output_text[1:]
                    return True, json.loads(output_text)
                except json.JSONDecodeError as e:
                    logger.error(f"无法解析命令输出为 JSON: {result.stdout}\n错误: {e}")
                    return False, f"解析命令输出为 JSON 失败: {e}\n原始输出: {result.stdout.strip()}"
            else:
                return True, result.stdout.strip()

    except FileNotFoundError:
        command_name = command_parts[0] if command_parts else 'command'
        logger.error(f"命令未找到: {command_name}")
        return False, f"命令 '{command_name}' 未找到。请确保它已安装并在系统 PATH 中。"
    except subprocess.TimeoutExpired:
        logger.error(f"命令超时 (>{timeout}s): {log_command}")
        return False, f"命令执行超时 (>{timeout}秒)。"
    except Exception as e:
        logger.error(f"执行命令时发生异常: {e}")
        return False, f"执行命令时发生异常: {str(e)}"

def run_incus_command(command_args, parse_json=True, timeout=60):
    return run_command(['incus'] + command_args, parse_json, timeout)
