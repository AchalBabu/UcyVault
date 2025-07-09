from flask import Flask, render_template, session, redirect, url_for
from extensions import mysql, mail
from config import (
    MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB, SECRET_KEY,
    MAIL_SERVER, MAIL_PORT, MAIL_USE_TLS, MAIL_USERNAME, MAIL_PASSWORD
)
from auth import auth_bp, init_auth
from vault.passwords import passwords_bp
from vault.files import files_bp
from vault.notes import notes_bp

app = Flask(__name__)

# --- MySQL Configuration ---
app.config['MYSQL_HOST'] = MYSQL_HOST
app.config['MYSQL_USER'] = MYSQL_USER
app.config['MYSQL_PASSWORD'] = MYSQL_PASSWORD
app.config['MYSQL_DB'] = MYSQL_DB

# --- Secret Key for Session ---
app.secret_key = SECRET_KEY

# --- Mail Configuration ---
app.config['MAIL_SERVER'] = MAIL_SERVER
app.config['MAIL_PORT'] = MAIL_PORT
app.config['MAIL_USE_TLS'] = MAIL_USE_TLS
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD

# --- Initialize Extensions ---
mysql.init_app(app)
mail.init_app(app)

# --- Register Auth Blueprint (after routes are defined in init_auth) ---
init_auth()  # Defines all @auth_bp routes
app.register_blueprint(auth_bp)

# --- Register Vault Blueprints ---
app.register_blueprint(passwords_bp)
app.register_blueprint(files_bp)
app.register_blueprint(notes_bp)

# --- Routes ---
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('auth.login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    return render_template('dashboard.html', username=session['username'])

# --- Run Server ---
if __name__ == '__main__':
    app.run(debug=True)
