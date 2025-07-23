# config.py
import os

# --- Railway MySQL Configuration ---
MYSQL_HOST = 'maglev.proxy.rlwy.net'
MYSQL_PORT = 23506
MYSQL_USER = 'root'
MYSQL_PASSWORD = 'GhilEnwvMZgEqvndhxPkVClJVhzTzpvh'
MYSQL_DB = 'railway'

# --- Secret Key for Sessions ---
SECRET_KEY = 'ucysec_super_secret_key'
SESSION_PERMANENT = False
SESSION_TYPE = "filesystem"

# --- Mail Configuration ---
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'theachal123@gmail.com'
MAIL_PASSWORD = 'fvfp irqz pcdx cipm'  # Gmail App Password



if os.environ.get('RENDER'):
    UPLOAD_FOLDER = '/tmp'  # ✅ Render pe safe
else:
    UPLOAD_FOLDER = 'uploads'  # ✅ Localhost pe safe

