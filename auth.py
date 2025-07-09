from flask import Blueprint, render_template, request, redirect, session, url_for, flash, current_app
from crypto_utils import hash_password, verify_password
from extensions import mysql, mail
import MySQLdb.cursors
import random
import logging
from datetime import datetime, timedelta
from flask_mail import Message
import os

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)


def send_otp_email(receiver_email, otp):
    try:
        msg = Message(
            subject='Your OTP Code - UcyVault',
            sender=current_app.config['MAIL_USERNAME'],
            recipients=[receiver_email],
            body=f'Your OTP code is: {otp}\nIt will expire in 5 minutes.\n\nNever share this code with anyone.'
        )
        mail.send(msg)
    except Exception as e:
        logger.error("Failed to send OTP email: %s", str(e))


def generate_otp():
    return str(random.randint(100000, 999999))


# 💡 No need to register blueprint inside init_auth; define routes here only.
def init_auth():
    @auth_bp.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            email_or_phone = request.form.get('email_or_phone', '').strip()
            security_question = request.form.get('security_question', '').strip()
            security_answer = request.form.get('security_answer', '').strip()

            if not all([username, password, email_or_phone, security_question, security_answer]):
                flash('All fields are required.', 'warning')
                return render_template('register.html')

            hashed_pw = hash_password(password)

            try:
                cur = mysql.connection.cursor()
                cur.execute("""
                    INSERT INTO users (username, password_hash, email_or_phone, security_question, security_answer)
                    VALUES (%s, %s, %s, %s, %s)
                """, (username, hashed_pw, email_or_phone, security_question, security_answer))
                mysql.connection.commit()
                flash('Registration successful!', 'success')
                return redirect(url_for('auth.login'))
            except Exception as e:
                logger.exception("Registration error:")
                flash('Username already exists or an error occurred.', 'danger')
            finally:
                cur.close()

        return render_template('register.html')
    @auth_bp.route('/delete-account', methods=['POST'])
    def delete_account():
        if 'user_id' not in session:
            flash("Unauthorized access.", "danger")
            return redirect(url_for('auth.login'))

        user_id = session['user_id']

        try:
            cur = mysql.connection.cursor()

            # Delete files from disk
            cur.execute("SELECT encrypted_name FROM files WHERE user_id = %s", (user_id,))
            files = cur.fetchall()
            for f in files:
                filepath = os.path.join('encrypted_data/files', f[0])
                if os.path.exists(filepath):
                    os.remove(filepath)

            # Delete user-related data
            cur.execute("DELETE FROM files WHERE user_id = %s", (user_id,))
            cur.execute("DELETE FROM notes WHERE user_id = %s", (user_id,))
            cur.execute("DELETE FROM passwords WHERE user_id = %s", (user_id,))
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            mysql.connection.commit()
            cur.close()

            session.clear()
            flash("Your account and all associated data have been permanently deleted.", "success")
            return redirect(url_for('auth.login'))
        except Exception as e:
            logger.exception("Error deleting account:")
            flash("Something went wrong while deleting your account.", "danger")
            return redirect(url_for('dashboard'))
    
    

    @auth_bp.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

            if not username or not password:
                flash('Please enter both username and password.', 'warning')
                return render_template('login.html')

            cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            cur.close()

            if user and verify_password(user['password_hash'], password):
                session['pre_otp_user'] = {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email_or_phone'],
                    'master_key': password
                }

                otp = generate_otp()
                session['otp'] = otp
                session['otp_expiry'] = (datetime.now() + timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')

                send_otp_email(user['email_or_phone'], otp)
                flash("OTP sent to your email.", "info")
                return redirect(url_for('auth.verify_otp'))
            else:
                flash('Invalid credentials.', 'danger')

        return render_template('login.html')

    @auth_bp.route('/verify-otp', methods=['GET', 'POST'])
    def verify_otp():
        if request.method == 'POST':
            entered_otp = request.form.get('otp')
            actual_otp = session.get('otp')
            expiry_str = session.get('otp_expiry')

            if not actual_otp or not expiry_str:
                flash("Session expired. Please login again.", 'danger')
                return redirect(url_for('auth.login'))

            expiry = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S')
            if datetime.now() > expiry:
                flash("OTP expired. Please request a new one.", 'danger')
                return redirect(url_for('auth.resend_otp'))

            if entered_otp == actual_otp:
                user = session.pop('pre_otp_user', None)
                if user:
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['master_key'] = user['master_key']
                    session.pop('otp', None)
                    session.pop('otp_expiry', None)
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))

            flash("Invalid OTP", "danger")

        return render_template('verify_otp.html')

    @auth_bp.route('/resend-otp')
    def resend_otp():
        user = session.get('pre_otp_user')
        if not user:
            flash("Session expired. Please login again.", 'danger')
            return redirect(url_for('auth.login'))

        otp = generate_otp()
        session['otp'] = otp
        session['otp_expiry'] = (datetime.now() + timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
        send_otp_email(user['email'], otp)
        flash('OTP resent to your email.', 'info')
        return redirect(url_for('auth.verify_otp'))

    @auth_bp.route('/forgot-password', methods=['GET', 'POST'])
    def forgot_password():
        if request.method == 'POST':
            username = request.form['username'].strip()

            cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cur.execute("SELECT * FROM users WHERE username=%s", (username,))
            user = cur.fetchone()
            cur.close()

            if user:
                session['reset_user'] = user['username']
                session['reset_email'] = user['email_or_phone']
                session['security_question'] = user['security_question']
                session['security_answer'] = user['security_answer']
                return redirect(url_for('auth.verify_security'))
            else:
                flash("Username not found", "danger")

        return render_template('forgot_password.html')

    @auth_bp.route('/verify-security', methods=['GET', 'POST'])
    def verify_security():
        if request.method == 'POST':
            answer = request.form['security_answer'].strip().lower()
            real_answer = session.get('security_answer', '').strip().lower()

            if answer == real_answer:
                otp = generate_otp()
                session['reset_otp'] = otp
                session['otp_expiry'] = (datetime.now() + timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
                send_otp_email(session.get('reset_email'), otp)
                flash("OTP sent to your email.", "info")
                print("Reset OTP:", otp)
                return redirect(url_for('auth.otp_reset'))
            else:
                flash("Incorrect answer", "danger")

        return render_template('verify_security.html', question=session.get('security_question'))

    @auth_bp.route('/otp-reset', methods=['GET', 'POST'])
    def otp_reset():
        if request.method == 'POST':
            otp_input = request.form['otp'].strip()
            new_password = request.form['new_password']
            actual_otp = session.get('reset_otp')
            expiry_str = session.get('otp_expiry')

            if not actual_otp or not expiry_str:
                flash("Session expired", "danger")
                return redirect(url_for('auth.forgot_password'))

            if datetime.now() > datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S'):
                flash("OTP expired", "danger")
                return redirect(url_for('auth.forgot_password'))

            if otp_input == actual_otp:
                username = session.get('reset_user')
                hashed_pw = hash_password(new_password)

                cur = mysql.connection.cursor()
                cur.execute("UPDATE users SET password_hash=%s WHERE username=%s", (hashed_pw, username))
                mysql.connection.commit()
                cur.close()

                session.clear()
                flash("Password reset successful!", "success")
                return redirect(url_for('auth.login'))
            else:
                flash("Invalid OTP", "danger")

        return render_template('otp_reset.html')

    @auth_bp.route('/logout')
    def logout():
        session.clear()
        flash('Logged out successfully!', 'success')
        return redirect(url_for('auth.login'))
