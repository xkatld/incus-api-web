from flask import request
from flask_restx import Namespace, Resource, fields
import time
from ..auth import api_key_required
from ..services import incus_commands, nat_manager
from ..db import query_db, sync_container_to_db, remove_container_from_db, get_nat_rules_for_container, check_nat_rule_exists_in_db, add_nat_rule_to_db, get_nat_rule_by_id, remove_nat_rule_from_db, get_quick_commands, add_quick_command, remove_quick_command_from_db

api = Namespace('v1', description='Incus Web API v1', decorators=[api_key_required])

container_create_model = api.model('创建容器模型', {'name': fields.String(required=True), 'image': fields.String(required=True)})
container_action_model = api.model('容器操作模型', {'action': fields.String(required=True, enum=['start', 'stop', 'restart', 'delete'])})
exec_command_model = api.model('执行命令模型', {'command': fields.String(required=True)})
nat_rule_model = api.model('NAT 规则模型', {'host_port': fields.Integer(required=True), 'container_port': fields.Integer(required=True), 'protocol': fields.String(required=True, enum=['tcp', 'udp'])})
response_model = api.model('通用响应模型', {'状态': fields.String, '消息': fields.String})

@api.route('/containers')
class ContainerList(Resource):
    def get(self):
        success, containers_data = incus_commands.run_incus_command(['list', '--format', 'json'])
        if success:
            return containers_data, 200
        api.abort(500, f'获取容器列表失败: {containers_data}')

    @api.expect(container_create_model)
    def post(self):
        data = request.json
        success, output = incus_commands.run_incus_command(['launch', data['image'], data['name']], parse_json=False)
        if success:
            return {'状态': '成功', '消息': f'容器 {data["name"]} 创建操作已提交。'}, 200
        api.abort(500, f'创建容器 {data["name"]} 失败: {output}')

@api.route('/containers/<string:name>/action')
class ContainerAction(Resource):
    @api.expect(container_action_model)
    def post(self, name):
        action = request.json.get('action')
        command = [action, name]
        if action in ['stop', 'restart', 'delete']:
            command.append('--force')
        
        success, output = incus_commands.run_incus_command(command, parse_json=False)
        if success:
            return {'状态': '成功', '消息': f'容器 {name} {action} 成功。'}, 200
        api.abort(500, f'容器 {name} {action} 失败: {output}')

@api.route('/containers/<string:name>/exec')
class ContainerExec(Resource):
    @api.expect(exec_command_model)
    def post(self, name):
        command = request.json.get('command')
        success, output = incus_commands.run_incus_command(['exec', name, '--', 'bash', '-c', command], parse_json=False)
        return {'状态': '成功' if success else '错误', '输出': output}, 200 if success else 500