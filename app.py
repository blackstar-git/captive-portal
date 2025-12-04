from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
import secrets
import string
import qrcode
import io
import base64
import os
from datetime import datetime, timedelta
import sendgrid
from sendgrid.helpers.mail import Mail
import subprocess
import tempfile
import threading
import hashlib
import time
from qrcode.image.pure import PyPNGImage

app = Flask(__name__)
app.config['SECRET_KEY'] = 'GENERATE_KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configuration
SENDGRID_API_KEY = 'CONFIGURE_ON_SENGRID_FOR_EMAIL_SERVICES'
FROM_EMAIL = 'GMAIL_ID_TO_SEND_LOGIN_DETAILS'
WIREGUARD_SERVER_PUBLIC_KEY = 'GENERATE_SERVER_KEYS'
WIREGUARD_SERVER_ENDPOINT = 'YOUR_CLOUD_IP:PORT'
WIREGUARD_SUBNET = '10.XX.X.X/24'

# Password reset tokens storage
password_reset_tokens = {}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))
    vpn_config = db.Column(db.Text)
    client_private_key = db.Column(db.String(100))
    client_public_key = db.Column(db.String(100))
    client_ip = db.Column(db.String(15))
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_wireguard_keys():
    """Generate WireGuard private and public key pair"""
    try:
        private_key_process = subprocess.run(['wg', 'genkey'], capture_output=True, text=True, check=True)
        private_key = private_key_process.stdout.strip()
        
        public_key_process = subprocess.run(['wg', 'pubkey'], input=private_key, capture_output=True, text=True, check=True)
        public_key = public_key_process.stdout.strip()
        
        return private_key, public_key
    except subprocess.CalledProcessError:
        print("WireGuard tools not available, using Python fallback")
        return secrets.token_hex(32), secrets.token_hex(32)

def get_available_client_ip():
    """Get an available IP address from the WireGuard subnet"""
    used_ips = {cred.client_ip for cred in Credential.query.all() if cred.client_ip}
    
    for i in range(102, 251):
        ip = f'10.200.0.{i}'
        if ip not in used_ips:
            return ip
    
    return f'10.200.0.{secrets.choice(range(102, 251))}'

def generate_credentials():
    """Generate random username and password"""
    username = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(8))
    password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    return username, password

def read_wireguard_config():
    """Read and parse the current WireGuard config"""
    try:
        with open('/etc/wireguard/wg0.conf', 'r') as f:
            content = f.read()

        lines = content.split('\n')
        interface_section = []
        peer_sections = []
        current_section = []

        for line in lines:
            line = line.strip()
            if line.startswith('[') and line.endswith(']'):
                if current_section:
                    if '[Interface]' in current_section[0]:
                        interface_section = current_section
                    else:
                        peer_sections.append(current_section)
                current_section = [line]
            elif line and not line.startswith('#'):
                current_section.append(line)

        if current_section:
            if '[Interface]' in current_section[0]:
                interface_section = current_section
            else:
                peer_sections.append(current_section)

        return interface_section, peer_sections
    except Exception as e:
        print(f"Error reading WireGuard config: {e}")
        return [], []

def write_wireguard_config(interface_section, peer_sections):
    """Write back the WireGuard config in clean format"""
    try:
        content = interface_section + [''] + [item for sublist in [peer + [''] for peer in peer_sections[:-1]] for item in sublist] + peer_sections[-1]
        with open('/etc/wireguard/wg0.conf', 'w') as f:
            f.write('\n'.join(content))
        return True
    except Exception as e:
        print(f"Error writing WireGuard config: {e}")
        return False

def execute_wireguard_command(command, input_data=None, timeout=10):
    """Execute WireGuard command with error handling"""
    try:
        result = subprocess.run(command, input=input_data, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)

def add_peer_live(public_key, client_ip):
    """Add a peer to WireGuard using live commands - ZERO DOWNTIME"""
    print(f"Attempting to add peer {client_ip} live...")
    success, error = execute_wireguard_command(['wg', 'set', 'wg0', 'peer', public_key, 'allowed-ips', f'{client_ip}/32'])
    
    if success:
        print(f"Successfully added peer {client_ip} live")
        update_config_from_live()
        return True
    else:
        print(f"Live peer addition failed: {error}")
        return False

def remove_peer_live(public_key):
    """Remove a peer from WireGuard using live commands - ZERO DOWNTIME"""
    print(f"Attempting to remove peer with public key {public_key[:20]}... live")
    success, error = execute_wireguard_command(['wg', 'set', 'wg0', 'peer', public_key, 'remove'])
    
    if success:
        print("Successfully removed peer live")
        update_config_from_live()
        return True
    else:
        print(f"Live peer removal failed: {error}")
        return False

def update_config_from_live():
    """Update config file from live WireGuard configuration"""
    success, error = execute_wireguard_command(['wg', 'showconf', 'wg0'])
    if success:
        with open('/etc/wireguard/wg0.conf', 'w') as f:
            f.write(success)
        print("Config file updated from live configuration")
        return True
    else:
        print(f"Failed to get live config: {error}")
        return False

def add_client_to_wireguard(public_key, client_ip):
    """Add client to WireGuard - TRUE ZERO DOWNTIME"""
    print(f"Starting to add client {client_ip} with public key: {public_key[:20]}...")
    
    if add_peer_live(public_key, client_ip):
        print(f"Successfully added client {client_ip} with ZERO DOWNTIME")
        return True
    else:
        print("Live addition failed, updating config file only (no WireGuard restart)")
        return update_config_only(public_key, client_ip)

def remove_client_from_wireguard(public_key):
    """Remove client from WireGuard - TRUE ZERO DOWNTIME with error handling"""
    if not public_key or public_key.strip() == "":
        print("Invalid or empty public key, skipping WireGuard removal")
        return True

    print(f"Starting to remove client with public key: {public_key[:20]}...")
    
    if remove_peer_live(public_key):
        print(f"Successfully removed client with ZERO DOWNTIME")
        return True
    else:
        print("Live removal failed, updating config file only (no WireGuard restart)")
        return remove_from_config_only(public_key)

def update_config_only(public_key, client_ip):
    """Update config file only without restarting WireGuard"""
    interface_section, peer_sections = read_wireguard_config()

    # Remove any existing peer with same public key or IP
    new_peer_sections = [
        peer for peer in peer_sections 
        if f'PublicKey = {public_key}' not in '\n'.join(peer) 
        and f'AllowedIPs = {client_ip}/32' not in '\n'.join(peer)
    ]

    # Add new peer
    new_peer = [
        f'# Client {client_ip} - {datetime.utcnow().strftime("%Y-%m-%d %H:%M")}',
        '[Peer]',
        f'PublicKey = {public_key}',
        f'AllowedIPs = {client_ip}/32'
    ]
    new_peer_sections.append(new_peer)

    if write_wireguard_config(interface_section, new_peer_sections):
        print(f"Config file updated for client {client_ip} (no WireGuard restart)")
        return True
    return False

def remove_from_config_only(public_key):
    """Remove client from config only without restarting WireGuard"""
    if not public_key or public_key.strip() == "":
        print("Invalid public key for config removal")
        return True

    interface_section, peer_sections = read_wireguard_config()
    
    # Remove peer with matching public key
    new_peer_sections = [
        peer for peer in peer_sections 
        if f'PublicKey = {public_key}' not in '\n'.join(peer)
    ]

    if len(new_peer_sections) < len(peer_sections):
        if write_wireguard_config(interface_section, new_peer_sections):
            print("Config file updated (no WireGuard restart)")
            return True
        return False

    print(f"No client found with public key: {public_key[:20]}... (may already be removed)")
    return True

def send_email(to_email, subject, content):
    """Send email using SendGrid"""
    try:
        sg = sendgrid.SendGridAPIClient(SENDGRID_API_KEY)
        mail = Mail(from_email=FROM_EMAIL, to_emails=to_email, subject=subject, html_content=content)
        sg.send(mail)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def auto_revoke_expired_credentials():
    """Auto-revoke credentials that expired more than 1 hour ago"""
    try:
        expired_time_threshold = datetime.utcnow() - timedelta(hours=1)
        expired_creds = Credential.query.filter(Credential.expires_at < expired_time_threshold).all()

        for cred in expired_creds:
            print(f"Auto-revoking expired credential: {cred.username}")
            if cred.client_public_key:
                remove_client_from_wireguard(cred.client_public_key)
            db.session.delete(cred)

        if expired_creds:
            db.session.commit()
            print(f"Auto-revoked {len(expired_creds)} expired credentials")
    except Exception as e:
        print(f"Auto-revoke expired credentials error: {e}")

def get_user_credential_count(user_id):
    """Get count of active + expired credentials for a user"""
    return Credential.query.filter_by(user_id=user_id).count()

def cleanup_expired_credentials():
    """Remove expired credentials from WireGuard config and auto-revoke old ones"""
    try:
        # Remove from WireGuard any recently expired credentials
        recent_expired_creds = Credential.query.filter(
            Credential.expires_at < datetime.utcnow(),
            Credential.is_used == False
        ).all()

        for cred in recent_expired_creds:
            print(f"Removing expired credential from WireGuard: {cred.username}")
            if cred.client_public_key:
                remove_client_from_wireguard(cred.client_public_key)
            cred.is_used = True

        if recent_expired_creds:
            db.session.commit()
            print(f"Removed {len(recent_expired_creds)} expired credentials from WireGuard")

        # Auto-revoke credentials that expired more than 1 hour ago
        auto_revoke_expired_credentials()
    except Exception as e:
        print(f"Cleanup expired credentials error: {e}")

def generate_reset_token():
    """Generate a unique password reset token"""
    return secrets.token_urlsafe(32)

def run_async_task(target_function, *args):
    """Run a function asynchronously in a thread"""
    thread = threading.Thread(target=target_function, args=args, daemon=True)
    thread.start()

def generate_qr_code(data):
    """Generate QR code from data"""
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    
    try:
        img = qr.make_image(fill_color="black", back_color="white")
    except:
        img = qr.make_image(image_factory=PyPNGImage)
    
    img_buffer = io.BytesIO()
    img.save(img_buffer, 'PNG')
    img_buffer.seek(0)
    return base64.b64encode(img_buffer.getvalue()).decode()

# Route decorators for cleanup
def with_cleanup(route_function):
    """Decorator to automatically cleanup expired credentials"""
    def wrapper(*args, **kwargs):
        cleanup_expired_credentials()
        return route_function(*args, **kwargs)
    wrapper.__name__ = route_function.__name__
    return wrapper

@app.route('/')
@with_cleanup
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@with_cleanup
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        user = User(email=email, name=name, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@with_cleanup
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email, password=password).first()

        if user and user.is_active:
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
@with_cleanup
def logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
@with_cleanup
def dashboard():
    credentials = Credential.query.filter_by(user_id=current_user.id).order_by(Credential.created_at.desc()).all()
    total_credentials = get_user_credential_count(current_user.id)
    return render_template('dashboard.html', credentials=credentials, datetime=datetime.utcnow(), total_credentials=total_credentials)

@app.route('/generate_credentials')
@login_required
@with_cleanup
def generate_credential():
    try:
        # Check if user already has 3 credentials (active + expired)
        if get_user_credential_count(current_user.id) >= 3:
            flash('You can only have 3 credentials at a time (including expired ones). Please revoke some before generating new ones.', 'danger')
            return redirect(url_for('dashboard'))

        username, password = generate_credentials()
        client_private_key, client_public_key = generate_wireguard_keys()
        client_ip = get_available_client_ip()

        vpn_config = f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_ip}/24
DNS = 10.XXX.X.XXX

[Peer]
PublicKey = {WIREGUARD_SERVER_PUBLIC_KEY}
Endpoint = {WIREGUARD_SERVER_ENDPOINT}
AllowedIPs = 0.0.0.0/0
"""

        credential = Credential(
            user_id=current_user.id,
            username=username,
            password=password,
            vpn_config=vpn_config,
            client_private_key=client_private_key,
            client_public_key=client_public_key,
            client_ip=client_ip,
            expires_at=datetime.utcnow() + timedelta(hours=6)
        )
        db.session.add(credential)
        db.session.commit()

        # Add client to WireGuard asynchronously
        run_async_task(add_client_to_wireguard, client_public_key, client_ip)

        # Send email
        email_content = f"""
        <h3>Your Network Access Credentials</h3>
        <p><strong>Local Access Username:</strong> {username}</p>
        <p><strong>Local Access Password:</strong> {password}</p>
        <p><strong>VPN Client IP:</strong> {client_ip}</p>
        <p><strong>Expires:</strong> {credential.expires_at.strftime('%Y-%m-%d %H:%M')}</p>
        <p>Use these credentials at the captive portal when connected to the network locally.</p>
        <p>For remote access, download the VPN configuration from your dashboard.</p>
        """
        send_email(current_user.email, "Your Network Access Credentials", email_content)

        flash('Credentials generated successfully! Check your mail for password!!!', 'success')
        return redirect(url_for('dashboard'))

    except Exception as e:
        db.session.rollback()
        print(f"Error in generate_credential: {e}")
        flash(f'Error generating credentials: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/download_vpn/<int:credential_id>')
@login_required
@with_cleanup
def download_vpn(credential_id):
    try:
        credential = Credential.query.filter_by(id=credential_id, user_id=current_user.id).first_or_404()

        if credential.expires_at < datetime.utcnow():
            return render_template('credential_expired.html',
                                 credential=credential,
                                 message="This credential has expired and the VPN configuration is no longer available.")

        img_data = generate_qr_code(credential.vpn_config)
        return render_template('vpn_config.html', credential=credential, qr_code=img_data, config_text=credential.vpn_config)

    except Exception as e:
        print(f"Error in download_vpn: {e}")
        return render_template('credential_expired.html',
                             message="Error loading VPN configuration. This credential may have been revoked or expired.")

@app.route('/download_config_file/<int:credential_id>')
@login_required
@with_cleanup
def download_config_file(credential_id):
    credential = Credential.query.filter_by(id=credential_id, user_id=current_user.id).first_or_404()

    if credential.expires_at < datetime.utcnow():
        return render_template('credential_expired.html',
                             credential=credential,
                             message="This credential has expired and cannot be downloaded.")

    file_content = credential.vpn_config.encode('utf-8')
    filename = f'wg0-{credential.username}.conf'

    response = Response(file_content, mimetype='application/octet-stream')
    response.headers.set('Content-Disposition', 'attachment', filename=filename)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-cache'

    return response

@app.route('/revoke_credential/<int:credential_id>')
@login_required
@with_cleanup
def revoke_credential(credential_id):
    credential = Credential.query.filter_by(id=credential_id, user_id=current_user.id).first_or_404()

    try:
        if credential.client_public_key and not credential.is_used:
            run_async_task(remove_client_from_wireguard, credential.client_public_key)
            flash('Credential revoked! VPN access is being removed.', 'info')
        else:
            flash('Credential removed from dashboard.', 'info')

        db.session.delete(credential)
        db.session.commit()
        return redirect(url_for('dashboard'))

    except Exception as e:
        db.session.rollback()
        flash(f'Error revoking credential: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/api/verify_credentials', methods=['POST'])
@with_cleanup
def verify_credentials():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    credential = Credential.query.filter_by(username=username, password=password, is_used=False).first()

    if credential and credential.expires_at > datetime.utcnow():
        return jsonify({'success': True, 'message': 'Access granted'})

    return jsonify({'success': False, 'message': 'Invalid or expired credentials'})

@app.route('/forgot_password', methods=['GET', 'POST'])
@with_cleanup
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            token = generate_reset_token()
            expires_at = datetime.utcnow() + timedelta(minutes=10)

            password_reset_tokens[token] = {'user_id': user.id, 'expires_at': expires_at}

            reset_url = f"{request.host_url}reset_password/{token}"
            email_content = f"""
            <h3>Password Reset Request</h3>
            <p>You requested to reset your password for the University Network Access system.</p>
            <p>Click the link below to reset your password (valid for 10 minutes):</p>
            <p><a href="{reset_url}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a></p>
            <p>If you didn't request this, please ignore this email.</p>
            <p><strong>Link:</strong> {reset_url}</p>
            """

            if send_email(user.email, "Password Reset - University Network", email_content):
                flash('Password reset link has been sent to your email.', 'info')
            else:
                flash('Error sending email. Please try again later.', 'danger')
        else:
            flash('If that email exists in our system, a reset link has been sent.', 'info')

        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
@with_cleanup
def reset_password(token):
    token_data = password_reset_tokens.get(token)

    if not token_data or token_data['expires_at'] < datetime.utcnow():
        flash('Invalid or expired reset token.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('reset_password.html', token=token)

        user = User.query.get(token_data['user_id'])
        if user:
            user.password = password
            db.session.commit()
            password_reset_tokens.pop(token, None)
            flash('Password reset successfully! You can now login with your new password.', 'success')
            return redirect(url_for('login'))
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('forgot_password'))

    return render_template('reset_password.html', token=token)

@app.route('/credential_expired')
@login_required
@with_cleanup
def credential_expired():
    credential_id = request.args.get('credential_id')
    credential = Credential.query.filter_by(id=credential_id, user_id=current_user.id).first() if credential_id else None
    return render_template('credential_expired.html', credential=credential)

@app.errorhandler(404)
@with_cleanup
def not_found_error(error):
    flash('The page or credential you are looking for was not found.', 'warning')
    return redirect(url_for('dashboard'))

@app.after_request
def add_header(response):
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)