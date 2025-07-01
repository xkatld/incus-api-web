from flask import Blueprint
from flask_restx import Api
from .routes import api as ns_v1

api_bp = Blueprint('api', __name__, url_prefix='/api')

api = Api(
    api_bp,
    version='1.0',
    title='Incus Web API',
    description='用于管理 Incus 容器的 RESTful API',
    doc='/doc/'
)

api.add_namespace(ns_v1, path='/v1')