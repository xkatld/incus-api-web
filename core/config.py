import os
import secrets

DATABASE_NAME = 'incus_manager.db'
FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(16))
