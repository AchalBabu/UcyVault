from flask import Blueprint, render_template, request, redirect, session, url_for, flash
from flask_mysqldb import MySQLdb
from crypto_utils import encrypt_data, decrypt_data
from extensions import mysql  

passwords_bp = Blueprint('passwords', __name__)

@passwords_bp.route('/passwords', methods=['GET', 'POST'])
def password_vault():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        service = request.form['service']
        site_user = request.form['site_username']
        site_pass = request.form['site_password']
        master_key = session['master_key']

        encrypted = encrypt_data(site_pass, master_key)

        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO passwords (user_id, service_name, site_username, encrypted_password) VALUES (%s, %s, %s, %s)",
            (session['user_id'], service, site_user, encrypted)
        )
        mysql.connection.commit()
        cur.close()
        flash('Password saved successfully!', 'success')

    # Fetch existing passwords
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM passwords WHERE user_id=%s", (session['user_id'],))
    passwords = cur.fetchall()
    cur.close()

    decrypted_passwords = []
    for item in passwords:
        try:
            pwd = decrypt_data(item['encrypted_password'], session['master_key'])
        except:
            pwd = '[Decryption Failed]'
        decrypted_passwords.append({
            'id': item['id'],  # ✅ Needed for delete button
            'service': item['service_name'],
            'username': item['site_username'],
            'password': pwd
        })

    return render_template('passwords.html', passwords=decrypted_passwords)

@passwords_bp.route('/delete-password/<int:pass_id>', methods=['POST'])
def delete_password(pass_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM passwords WHERE id = %s AND user_id = %s", (pass_id, session['user_id']))
    mysql.connection.commit()
    cur.close()

    flash("Password deleted successfully.", "success")
    return redirect(url_for('passwords.password_vault'))  # ✅ Corrected route name
