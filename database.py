import sqlite3
from . import config

_app_logger = None

def init_db_helpers(app):
    global _app_logger
    _app_logger = app.logger

def get_db_connection():
    conn = sqlite3.connect(config.DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def query_db(query, args=(), one=False):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(query, args)
        if not query.strip().upper().startswith('SELECT'):
             conn.commit()
        rv = cur.fetchall()
    except sqlite3.Error as e:
        if _app_logger:
            _app_logger.error(f"Database query error: {e}\nQuery: {query}\nArgs: {args}")
        rv = []
        if conn:
             conn.rollback()
    finally:
        if conn:
            conn.close()
    return (rv[0] if rv else None) if one else rv
