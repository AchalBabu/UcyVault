from flask import Blueprint, request, render_template, redirect, session, send_file, flash, url_for, current_app
import os
from datetime import datetime
from werkzeug.utils import secure_filename
from extensions import mysql  
from crypto_utils import encrypt_data, decrypt_data, get_key, pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import MySQLdb.cursors

files_bp = Blueprint('files', __name__)

# 🛠 Dynamic upload folder (Render vs Local)
UPLOAD_FOLDER = '/tmp' if os.environ.get('RENDER') else 'encrypted_data/files/'

@files_bp.route('/files', methods=['GET', 'POST'])
def file_vault():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            master_key = session['master_key']
            key = get_key(master_key)
            iv = get_random_bytes(16)

            raw_data = file.read()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_data = iv + cipher.encrypt(pad(raw_data))

            filename = secure_filename(file.filename)
            encrypted_filename = f"{session['user_id']}_{datetime.now().timestamp()}_{filename}.enc"
            path = os.path.join(UPLOAD_FOLDER, encrypted_filename)

            try:
                with open(path, 'wb') as f:
                    f.write(encrypted_data)
            except Exception as e:
                flash(f"File upload failed: {str(e)}", "danger")
                return redirect(url_for('files.file_vault'))

            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO files (user_id, original_name, encrypted_name) VALUES (%s, %s, %s)",
                (session['user_id'], filename, encrypted_filename)
            )
            mysql.connection.commit()
            cur.close()

            flash('File uploaded and encrypted!', 'success')
            return redirect(url_for('files.file_vault'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM files WHERE user_id = %s", (session['user_id'],))
    files = cur.fetchall()
    cur.close()

    return render_template('files.html', files=files)

@files_bp.route('/download/<int:file_id>', methods=['POST'])
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    master_key = session['master_key']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM files WHERE id = %s AND user_id = %s", (file_id, session['user_id']))
    file = cur.fetchone()
    cur.close()

    if not file:
        flash('Unauthorized or file not found.', 'danger')
        return redirect(url_for('files.file_vault'))

    path = os.path.join(UPLOAD_FOLDER, file['encrypted_name'])
    if not os.path.exists(path):
        flash('Encrypted file missing from server.', 'danger')
        return redirect(url_for('files.file_vault'))

    with open(path, 'rb') as f:
        data = f.read()

    try:
        iv = data[:16]
        cipher = AES.new(get_key(master_key), AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(data[16:]))
    except Exception:
        flash("Decryption failed. Possibly wrong key.", "danger")
        return redirect(url_for('files.file_vault'))

    temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{file['original_name']}")
    with open(temp_path, 'wb') as f:
        f.write(decrypted)

    return send_file(temp_path, as_attachment=True, download_name=file['original_name'])

@files_bp.route('/delete-file/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM files WHERE id = %s AND user_id = %s", (file_id, session['user_id']))
    mysql.connection.commit()
    cur.close()

    flash("File deleted successfully.", "success")
    return redirect(url_for('files.file_vault'))
