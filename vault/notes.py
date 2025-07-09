from flask import Blueprint, render_template, request, redirect, session, url_for, flash
from flask_mysqldb import MySQLdb
from extensions import mysql  #
from crypto_utils import encrypt_data, decrypt_data

notes_bp = Blueprint('notes', __name__)

@notes_bp.route('/notes', methods=['GET', 'POST'])
def notes_vault():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        master_key = session['master_key']

        encrypted_content = encrypt_data(content, master_key)

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO notes (user_id, title, encrypted_content) VALUES (%s, %s, %s)",
                    (session['user_id'], title, encrypted_content))
        mysql.connection.commit()
        cur.close()
        flash('Note saved securely!', 'success')
        return redirect(url_for('notes.notes_vault'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM notes WHERE user_id = %s", (session['user_id'],))
    notes = cur.fetchall()
    cur.close()

    decrypted_notes = []
    for note in notes:
        try:
            decrypted = decrypt_data(note['encrypted_content'], session['master_key'])
        except:
            decrypted = '[Decryption Failed]'
        decrypted_notes.append({
            'id': note['id'],
            'title': note['title'],
            'content': decrypted,
            'created_at': note['created_at']
        })

    return render_template('notes.html', notes=decrypted_notes)

@notes_bp.route('/delete-note/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM notes WHERE id = %s AND user_id = %s", (note_id, session['user_id']))
    mysql.connection.commit()
    cur.close()
    flash('Note deleted.', 'info')
    return redirect(url_for('notes.notes_vault'))

