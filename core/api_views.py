from flask import request, current_app, jsonify
from flask_restx import Api, Resource, Namespace, fields
import time
import logging
from functools import wraps

from .auth import verify_api_key_hash
from .utils import run_incus_command, run_command
from .db_manager import (
    query_db, sync_container_to_db, remove_container_from_db,
    get_nat_rules_for_container, check_nat_rule_exists_in_db,
    add_nat_rule_to_db, get_nat_rule_by_id, remove_nat_rule_from_db,
    get_quick_commands, add_quick_command, remove_quick_command_from_db
)
from .incus_api import get_container_raw_info
from .nat_manager import perform_iptables_delete_for_rule

logger = logging.getLogger(__name__)

def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not verify_api_key_hash():
            return {'状态': '错误', '消息': '需要有效的 API 密钥哈希 (X-API-Key-Hash)。'}, 401
        return f(*args, **kwargs)
    return decorated

api = Namespace('v1', description='Incus Web API v1', decorators=[api_key_required])

container_create_model = api.model('创建容器模型', {
    'name': fields.String(required=True, description='容器名称'),
    'image': fields.String(required=True, description='镜像名称 (别名)'),
    'storage_pool': fields.String(description='存储池名称 (可选, 默认)'),
    'cpu_cores': fields.Integer(description='CPU 核心数 (可选)'),
    'cpu_allowance': fields.Integer(description='CPU 占用率 (%) (可选)'),
    'memory_mb': fields.Integer(description='内存大小 (MB) (可选)'),
    'disk_gb': fields.Integer(description='硬盘大小 (GB) (可选)'),
    'security_nesting': fields.Boolean(description='是否允许嵌套 (可选, 默认 False)'),
})

container_action_model = api.model('容器操作模型', {
    'action': fields.String(required=True, description='操作类型', enum=['start', 'stop', 'restart', 'delete']),
})

exec_command_model = api.model('执行命令模型', {
    'command': fields.String(required=True, description='要在容器内执行的命令'),
})

nat_rule_model = api.model('NAT 规则模型', {
    'host_port': fields.Integer(required=True, description='主机端口'),
    'container_port': fields.Integer(required=True, description='容器端口'),
    'protocol': fields.String(required=True, description='协议', enum=['tcp', 'udp']),
})

quick_command_model = api.model('快捷命令模型', {
    'name': fields.String(required=True, description='快捷命令名称'),
    'command': fields.String(required=True, description='要执行的命令'),
})

response_model = api.model('通用响应模型', {
    '状态': fields.String(description='操作状态 (成功/错误/警告)'),
    '消息': fields.String(description='操作结果信息'),
    'id': fields.Integer(description='操作相关的ID (如果适用)'),
    'rule_id': fields.Integer(description='NAT规则ID (如果适用)'),
    '输出': fields.String(description='命令输出 (如果适用)'),
})

container_info_model = api.model('容器信息模型', {
    'name': fields.String,
    'status': fields.String,
    'status_code': fields.Integer,
    'type': fields.String,
    'architecture': fields.String,
    'ephemeral': fields.Boolean,
    'created_at': fields.String,
    'profiles': fields.List(fields.String),
    'config': fields.Raw,
    'devices': fields.Raw,
    'state': fields.Raw,
    'description': fields.String,
    'ip': fields.String,
    'live_data_available': fields.Boolean,
    'message': fields.String,
})

nat_rule_info_model = api.model('NAT 规则信息模型', {
    'id': fields.Integer,
    'host_port': fields.Integer,
    'container_port': fields.Integer,
    'protocol': fields.String,
    'ip_at_creation': fields.String,
    'created_at': fields.String,
})

nat_rules_list_model = api.model('NAT 规则列表模型', {
    '状态': fields.String,
    '规则': fields.List(fields.Nested(nat_rule_info_model)),
})

quick_command_info_model = api.model('快捷命令信息模型', {
    'id': fields.Integer,
    'name': fields.String,
    'command': fields.String,
})

quick_commands_list_model = api.model('快捷命令列表模型', {
    '状态': fields.String,
    '命令': fields.List(fields.Nested(quick_command_info_model)),
})


@api.route('/containers')
class ContainerList(Resource):
    @api.doc('list_containers', description="获取所有 Incus 容器的列表")
    @api.marshal_list_with(container_info_model)
    def get(self):
        success_list, containers_data = run_incus_command(['list', '--format', 'json'])
        if success_list and isinstance(containers_data, list):
            # 简单处理，实际可根据需要丰富信息
            processed_data = []
            for item in containers_data:
                 info, _ = get_container_raw_info(item.get('name', ''))
                 if info: processed_data.append(info)
            return processed_data, 200
        api.abort(500, f'获取容器列表失败: {containers_data}')

    @api.doc('create_container', description="创建一个新的 Incus 容器")
    @api.expect(container_create_model)
    @api.marshal_with(response_model)
    def post(self):
        data = request.json
        name = data.get('name')
        image = data.get('image')
        if not name or not image:
            api.abort(400, '容器名称和镜像不能为空')
        if query_db('SELECT 1 FROM containers WHERE incus_name = ?', [name], one=True):
            api.abort(409, f'名称为 "{name}" 的容器已存在。')

        command = ['launch', image, name]
        if data.get('storage_pool'): command.extend(['-s', data['storage_pool']])
        try:
            if data.get('cpu_cores'): command.extend(['-c', f'limits.cpu={int(data["cpu_cores"])}'])
            if data.get('cpu_allowance'): command.extend(['-c', f'limits.cpu.allowance={int(data["cpu_allowance"])}%'])
            if data.get('memory_mb'): command.extend(['-c', f'limits.memory={int(data["memory_mb"])}MB'])
            if data.get('disk_gb'): command.extend(['-d', f'root,size={int(data["disk_gb"])}GB'])
            if data.get('security_nesting'): command.extend(['-c', 'security.nesting=true'])
        except ValueError:
            api.abort(400, '资源限制参数必须是有效的数字。')

        success, output = run_incus_command(command, parse_json=False, timeout=180)
        if success:
            time.sleep(5)
            _, list_output = run_incus_command(['list', name, '--format', 'json'])
            if isinstance(list_output, list) and list_output:
                c_data = list_output[0]
                sync_container_to_db(name, c_data.get('config',{}).get('image.description', image), c_data.get('status', 'Pending'), c_data.get('created_at'))
            else:
                 sync_container_to_db(name, image, 'Pending', None)
            return {'状态': '成功', '消息': f'容器 {name} 创建操作已提交。'}, 200
        else:
            api.abort(500, f'创建容器 {name} 失败: {output}')


@api.route('/containers/<string:name>')
@api.param('name', '容器名称')
class ContainerResource(Resource):
    @api.doc('get_container_info', description="获取指定容器的详细信息")
    @api.marshal_with(container_info_model)
    def get(self, name):
        info, error = get_container_raw_info(name)
        if info:
            return info, 200
        else:
            api.abort(404, error)


@api.route('/containers/<string:name>/action')
@api.param('name', '容器名称')
class ContainerActionResource(Resource):
    @api.doc('container_action', description="对容器执行操作 (start, stop, restart, delete)")
    @api.expect(container_action_model)
    @api.marshal_with(response_model)
    def post(self, name):
        action = request.json.get('action')
        commands = {'start': ['start', name], 'stop': ['stop', name, '--force'], 'restart': ['restart', name, '--force']}

        if action == 'delete':
            success_db, rules = get_nat_rules_for_container(name)
            if not success_db: api.abort(500, f'获取NAT规则失败: {rules}')
            failed_deletions = []
            warning_deletions = []
            for rule in rules:
                success_ipt, ipt_msg, is_bad = perform_iptables_delete_for_rule(rule)
                if not success_ipt:
                    if is_bad: warning_deletions.append(ipt_msg)
                    else: failed_deletions.append(ipt_msg)
                remove_nat_rule_from_db(rule['id'])
            if failed_deletions: api.abort(500, f"删除部分NAT规则失败: {'; '.join(failed_deletions)}")

            success_incus, incus_output = run_incus_command(['delete', name, '--force'], parse_json=False, timeout=120)
            if success_incus:
                remove_container_from_db(name)
                msg = f'容器 {name} 已删除。'
                if warning_deletions: msg += " 注意: 部分iptables规则未找到。"
                return {'状态': '成功', '消息': msg}, 200
            else:
                api.abort(500, f'删除容器 {name} 失败: {incus_output}')

        if action not in commands:
            api.abort(400, '无效的操作')

        success, output = run_incus_command(commands[action], parse_json=False, timeout=120)
        if success:
            time.sleep(3)
            _, list_output = run_incus_command(['list', name, '--format', 'json'])
            new_status = '未知'
            if isinstance(list_output, list) and list_output:
                new_status = list_output[0].get('status', '未知')
                sync_container_to_db(name, list_output[0].get('config', {}).get('image.description', 'N/A'), new_status, list_output[0].get('created_at'))
            return {'状态': '成功', '消息': f'容器 {name} {action} 成功，新状态: {new_status}。'}, 200
        else:
            api.abort(500, f'容器 {name} {action} 失败: {output}')


@api.route('/containers/<string:name>/exec')
@api.param('name', '容器名称')
class ContainerExecResource(Resource):
    @api.doc('exec_command', description="在容器内执行命令")
    @api.expect(exec_command_model)
    @api.marshal_with(response_model)
    def post(self, name):
        command_to_exec = request.json.get('command')
        if not command_to_exec:
            api.abort(400, '命令不能为空')
        command_parts = ['exec', name, '--', 'bash', '-c', command_to_exec]
        success, output = run_incus_command(command_parts, parse_json=False, timeout=300)
        status_code = 200 if success else 500
        return {'状态': '成功' if success else '错误', '输出': output}, status_code


@api.route('/containers/<string:name>/nat')
@api.param('name', '容器名称')
class ContainerNatResource(Resource):
    @api.doc('list_nat_rules', description="列出容器的 NAT 规则")
    @api.marshal_with(nat_rules_list_model)
    def get(self, name):
        success, rules = get_nat_rules_for_container(name)
        if success:
            return {'状态': '成功', '规则': rules}, 200
        else:
            api.abort(500, rules)

    @api.doc('add_nat_rule', description="为容器添加 NAT 规则")
    @api.expect(nat_rule_model)
    @api.marshal_with(response_model)
    def post(self, name):
        data = request.json
        try:
            host_port = int(data.get('host_port'))
            container_port = int(data.get('container_port'))
            protocol = data.get('protocol')
            if not (1 <= host_port <= 65535 and 1 <= container_port <= 65535) or protocol not in ['tcp', 'udp']:
                raise ValueError("端口或协议无效")
        except (ValueError, TypeError, AttributeError):
            api.abort(400, '端口号无效或协议无效')

        db_ok, exists = check_nat_rule_exists_in_db(name, host_port, protocol)
        if not db_ok: api.abort(500, f'检查规则失败: {exists}')
        if exists: return {'状态': '警告', '消息': '规则已存在'}, 200

        info, error = get_container_raw_info(name)
        if not info: api.abort(404, f'获取容器信息失败: {error}')
        if info.get('status') != 'Running': api.abort(400, '容器未运行')
        container_ip = info.get('ip')
        if not container_ip or container_ip == 'N/A': api.abort(500, '无法获取容器 IP')

        iptables_cmd = ['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', protocol, '--dport', str(host_port), '-j', 'DNAT', '--to-destination', f'{container_ip}:{container_port}']
        success_ipt, output = run_command(iptables_cmd, parse_json=False)

        if success_ipt:
            rule_details = {'container_name': name, 'host_port': host_port, 'container_port': container_port, 'protocol': protocol, 'ip_at_creation': container_ip}
            db_add_ok, db_res = add_nat_rule_to_db(rule_details)
            if db_add_ok:
                return {'状态': '成功', '消息': 'NAT 规则添加成功。', 'rule_id': db_res}, 200
            else:
                return {'状态': '警告', '消息': f'iptables 成功，但数据库记录失败: {db_res}'}, 200
        else:
            api.abort(500, f'添加 NAT 规则失败: {output}')


@api.route('/containers/nat/<int:rule_id>')
@api.param('rule_id', 'NAT 规则 ID')
class NatRuleResource(Resource):
    @api.doc('delete_nat_rule', description="删除指定的 NAT 规则")
    @api.marshal_with(response_model)
    def delete(self, rule_id):
        success_db, rule = get_nat_rule_by_id(rule_id)
        if not success_db: api.abort(500, f'获取规则失败: {rule}')
        if not rule: return {'状态': '警告', '消息': '规则记录未找到'}, 200

        success_ipt, ipt_msg, is_bad = perform_iptables_delete_for_rule(rule)
        if success_ipt or is_bad:
            db_del_ok, db_msg = remove_nat_rule_from_db(rule_id)
            msg = 'NAT 规则已删除。'
            if is_bad: msg = '数据库记录已删除 (iptables 中未找到)。'
            if not db_del_ok: msg += f' 但数据库移除失败: {db_msg}'
            return {'状态': '成功' if db_del_ok else '警告', '消息': msg}, 200
        else:
            api.abort(500, f'删除 NAT 规则失败: {ipt_msg}')


@api.route('/quick-commands')
class QuickCommandList(Resource):
    @api.doc('list_quick_commands', description="获取快捷命令列表")
    @api.marshal_with(quick_commands_list_model)
    def get(self):
        success, commands = get_quick_commands()
        if success:
            return {'状态': '成功', '命令': commands}, 200
        else:
            api.abort(500, commands)

    @api.doc('add_quick_command', description="添加新的快捷命令")
    @api.expect(quick_command_model)
    @api.marshal_with(response_model)
    def post(self):
        data = request.json
        name = data.get('name')
        command = data.get('command')
        if not name or not command:
            api.abort(400, '名称和命令不能为空')
        success, result = add_quick_command(name, command)
        if success:
            return {'状态': '成功', '消息': '快捷命令添加成功。', 'id': result}, 200
        else:
            status_code = 409 if "已存在" in str(result) else 500
            api.abort(status_code, result)


@api.route('/quick-commands/<int:command_id>')
@api.param('command_id', '快捷命令 ID')
class QuickCommandResource(Resource):
    @api.doc('delete_quick_command', description="删除指定的快捷命令")
    @api.marshal_with(response_model)
    def delete(self, command_id):
        success, message = remove_quick_command_from_db(command_id)
        if success:
            return {'状态': '成功', '消息': message}, 200
        else:
            api.abort(500, message)
