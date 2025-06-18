# import os
# from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
# from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# from flask_mail import Mail, Message
# import pyotp
# import clamd
# import logging
# from datetime import datetime, timedelta
# import magic
# import platform
# from werkzeug.security import generate_password_hash, check_password_hash
# from dotenv import load_dotenv
# from pymongo import MongoClient
# from bson.objectid import ObjectId

# # Load environment variables
# load_dotenv()

# # Default configuration
# DEFAULT_CONFIG = {
#     'SECRET_KEY': 'dev-secret-key-change-in-production',
#     'MAIL_SERVER': 'smtp.gmail.com',
#     'MAIL_PORT': 587,
#     'MAIL_USERNAME': 'your-email@gmail.com',  # Replace with your Gmail
#     'MAIL_PASSWORD': 'your-app-password',     # Replace with your app password
#     'DATABASE_URL': 'sqlite:///secure_usb.db'
# }

# app = Flask(__name__)

# # Set configuration with defaults
# app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', DEFAULT_CONFIG['SECRET_KEY'])
# app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', DEFAULT_CONFIG['DATABASE_URL'])
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Suppress warning
# app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', DEFAULT_CONFIG['MAIL_SERVER'])
# app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', DEFAULT_CONFIG['MAIL_PORT']))
# app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', DEFAULT_CONFIG['MAIL_USERNAME'])
# app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', DEFAULT_CONFIG['MAIL_PASSWORD'])
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USE_SSL'] = False

# # Initialize extensions
# client = MongoClient(os.getenv('MONGODB_URI', 'mongodb://localhost:27017/'))
# db = client['secure_usb']
# users_collection = db['users']
# usb_drives_collection = db['usb_drives']
# access_logs_collection = db['access_logs']
# mail = Mail(app)
# login_manager = LoginManager()
# login_manager.init_app(app)
# login_manager.login_view = 'login'

# # Configure logging
# logging.basicConfig(filename='access.log', level=logging.INFO,
#                    format='%(asctime)s - %(levelname)s - %(message)s')

# # Initialize ClamAV
# try:
#     if platform.system() == 'Windows':
#         clam = clamd.ClamdNetworkSocket()
#     else:
#         clam = clamd.ClamdUnixSocket()
# except Exception as e:
#     logging.error(f"Failed to initialize ClamAV: {str(e)}")
#     clam = None

# class User(UserMixin):
#     def __init__(self, user_data):
#         self.id = str(user_data['_id'])
#         self.email = user_data['email']
#         self.password_hash = user_data['password_hash']
#         self.otp_secret = user_data['otp_secret']
#         self.last_login = user_data.get('last_login')
#         self.created_at = user_data.get('created_at', datetime.utcnow())

#     @staticmethod
#     def get(user_id):
#         user_data = users_collection.find_one({'_id': ObjectId(user_id)})
#         if user_data:
#             return User(user_data)
#         return None

#     @staticmethod
#     def get_by_email(email):
#         user_data = users_collection.find_one({'email': email})
#         if user_data:
#             return User(user_data)
#         return None

# @login_manager.user_loader
# def load_user(user_id):
#     return User.get(user_id)

# def scan_usb_drive(drive_path):
#     """Scan USB drive for malware using ClamAV"""
#     if not clam:
#         return {'is_safe': False, 'threats': [{'error': 'ClamAV not initialized'}]}
    
#     try:
#         result = clam.scan(drive_path)
#         is_safe = True
#         threats = []
        
#         for file_path, scan_result in result.items():
#             if scan_result[0] == 'FOUND':
#                 is_safe = False
#                 threats.append({
#                     'file': file_path,
#                     'threat': scan_result[1]
#                 })
        
#         return {
#             'is_safe': is_safe,
#             'threats': threats
#         }
#     except Exception as e:
#         logging.error(f"Error scanning USB drive: {str(e)}")
#         return {'is_safe': False, 'threats': [{'error': str(e)}]}

# def send_otp_email(user_email, otp):
#     msg = Message('Your OTP Code',
#                   sender=app.config['MAIL_USERNAME'],
#                   recipients=[user_email])
#     msg.body = f'Your OTP code is: {otp}'
#     mail.send(msg)

# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         email = request.form['email']
#         password = request.form['password']
        
#         user = User.get_by_email(email)
#         if user and check_password_hash(user.password_hash, password):
#             otp = pyotp.TOTP(user.otp_secret).now()
#             send_otp_email(email, otp)
#             session['user_id'] = str(user.id)
#             return redirect(url_for('verify_otp'))
        
#         flash('Invalid email or password')
#     return render_template('login.html')

# @app.route('/verify-otp', methods=['GET', 'POST'])
# def verify_otp():
#     if 'user_id' not in session:
#         return redirect(url_for('login'))
    
#     if request.method == 'POST':
#         otp = request.form['otp']
#         user = User.get(session['user_id'])
        
#         if pyotp.TOTP(user.otp_secret).verify(otp):
#             login_user(user)
#             users_collection.update_one(
#                 {'_id': ObjectId(user.id)},
#                 {'$set': {'last_login': datetime.utcnow()}}
#             )
#             return redirect(url_for('dashboard'))
        
#         flash('Invalid OTP')
#     return render_template('verify_otp.html')

# @app.route('/scan-usb', methods=['POST'])
# @login_required
# def scan_usb():
#     drive_path = request.form.get('drive_path')
#     if not drive_path:
#         return jsonify({'error': 'No drive path provided'}), 400
    
#     scan_result = scan_usb_drive(drive_path)
    
#     # Log the scan
#     access_logs_collection.insert_one({
#         'user_id': current_user.id,
#         'action': 'USB_SCAN',
#         'details': f"Drive: {drive_path}, Safe: {scan_result['is_safe']}",
#         'timestamp': datetime.utcnow()
#     })
    
#     return jsonify(scan_result)

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     user_drives = list(usb_drives_collection.find({'user_id': current_user.id}))
#     recent_logs = list(access_logs_collection.find(
#         {'user_id': current_user.id}
#     ).sort('timestamp', -1).limit(10))
    
#     return render_template('dashboard.html', 
#                          drives=user_drives,
#                          recent_logs=recent_logs)

# @app.route('/logout')
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for('index'))

# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     if request.method == 'POST':
#         email = request.form.get('email')
#         password = request.form.get('password')
#         confirm_password = request.form.get('confirm_password')

#         if not email or not password or not confirm_password:
#             flash('All fields are required.', 'danger')
#             return render_template('signup.html')

#         if password != confirm_password:
#             flash('Passwords do not match.', 'danger')
#             return render_template('signup.html')

#         existing_user = users_collection.find_one({'email': email})
#         if existing_user:
#             flash('Email already registered.', 'danger')
#             return render_template('signup.html')

#         user_data = {
#             'email': email,
#             'password_hash': generate_password_hash(password),
#             'otp_secret': pyotp.random_base32(),
#             'created_at': datetime.utcnow()
#         }
        
#         users_collection.insert_one(user_data)
#         flash('Registration successful! Please log in.', 'success')
#         return redirect(url_for('login'))

#     return render_template('signup.html')

# @app.route('/check-usb')
# @login_required
# def check_usb():
#     """Check if a USB drive is connected"""
#     try:
#         # For Windows, check common drive letters
#         if platform.system() == 'Windows':
#             import string
#             import win32file
#             drives = []
#             for letter in string.ascii_uppercase:
#                 if win32file.GetDriveType(f"{letter}:") == win32file.DRIVE_REMOVABLE:
#                     drives.append(f"{letter}:")
#             if drives:
#                 return jsonify({
#                     'detected': True,
#                     'drive_path': drives[0]  # Return the first detected drive
#                 })
#         else:
#             # For Linux/Unix systems
#             import glob
#             drives = glob.glob('/media/*/*') + glob.glob('/mnt/*')
#             if drives:
#                 return jsonify({
#                     'detected': True,
#                     'drive_path': drives[0]
#                 })
        
#         return jsonify({
#             'detected': False,
#             'drive_path': None
#         })
#     except Exception as e:
#         logging.error(f"Error checking USB drive: {str(e)}")
#         return jsonify({
#             'detected': False,
#             'drive_path': None
#         })

# @app.route('/verify-usb', methods=['POST'])
# @login_required
# def verify_usb():
#     """Send OTP for USB verification"""
#     try:
#         # Get the first detected drive
#         if platform.system() == 'Windows':
#             import string
#             import win32file
#             drives = []
#             for letter in string.ascii_uppercase:
#                 if win32file.GetDriveType(f"{letter}:") == win32file.DRIVE_REMOVABLE:
#                     drives.append(f"{letter}:")
#             drive_path = drives[0] if drives else None
#         else:
#             import glob
#             drives = glob.glob('/media/*/*') + glob.glob('/mnt/*')
#             drive_path = drives[0] if drives else None

#         if not drive_path:
#             return jsonify({'success': False, 'error': 'No USB drive detected'})

#         # Scan the drive for malware
#         scan_result = scan_usb_drive(drive_path)
#         if not scan_result['is_safe']:
#             return jsonify({
#                 'success': False,
#                 'error': 'Malware detected on drive',
#                 'threats': scan_result['threats']
#             })

#         # Send OTP to user's email
#         if send_otp_email(current_user.email, pyotp.TOTP(current_user.otp_secret).now()):
#             # Store the drive path in session for verification
#             session['pending_drive_path'] = drive_path
#             return jsonify({'success': True})
#         else:
#             logging.error("Failed to send OTP email")
#             return jsonify({'success': False, 'error': 'Failed to send OTP. Please check your email configuration.'})

#     except Exception as e:
#         logging.error(f"Error verifying USB drive: {str(e)}")
#         return jsonify({'success': False, 'error': str(e)})

# @app.route('/verify-usb-otp', methods=['POST'])
# @login_required
# def verify_usb_otp():
#     """Verify OTP for USB access"""
#     if 'pending_drive_path' not in session:
#         return jsonify({'success': False, 'error': 'No pending USB verification'})

#     otp = request.form.get('otp')
#     if not otp:
#         return jsonify({'success': False, 'error': 'No OTP provided'})

#     # Verify OTP
#     user = User.get(session['user_id'])
#     if user and pyotp.TOTP(user.otp_secret).verify(otp):
#         drive_path = session.pop('pending_drive_path')
        
#         # Log successful verification
#         access_logs_collection.insert_one({
#             'user_id': user.id,
#             'action': 'USB_ACCESS_GRANTED',
#             'details': f"Drive {drive_path} access granted after OTP verification",
#             'timestamp': datetime.utcnow()
#         })

#         return jsonify({
#             'success': True,
#             'drive_path': drive_path
#         })
#     else:
#         return jsonify({'success': False, 'error': 'Invalid OTP'})

# @app.route('/add-drive', methods=['POST'])
# @login_required
# def add_drive():
#     drive_data = {
#         'user_id': current_user.id,
#         'name': request.form['name'],
#         'serial_number': request.form['serial_number'],
#         'added_at': datetime.utcnow()
#     }
#     usb_drives_collection.insert_one(drive_data)
#     flash('USB drive added successfully')
#     return redirect(url_for('dashboard'))

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=8080, debug=True, use_reloader=False) 
from flask import Flask, render_template, request, jsonify, send_file
import os
import time

app = Flask(__name__)

# --- Simulated State ---
PD_STATE = {
    "active": False,
    "insert_count": 0,
    "needs_otp": False,
    "otp": "123456",  # For demo only
    "otp_verified": False,
    "scanned": False,
    "safe": True,
    "threats": [],
    "files": [
        {"name": "document.txt", "type": "file", "size": "2 KB", "modified": "2024-06-01 10:00", "path": "document.txt"},
        {"name": "photos", "type": "directory", "size": "-", "modified": "2024-06-01 09:00", "path": "photos"},
        {"name": "virus.exe", "type": "file", "size": "1 MB", "modified": "2024-06-01 08:00", "path": "virus.exe"},
    ]
}

# --- Simulated PD Insert/Remove ---
def simulate_pd_insert():
    PD_STATE["active"] = True
    PD_STATE["insert_count"] += 1
    PD_STATE["needs_otp"] = True
    PD_STATE["otp_verified"] = False
    PD_STATE["scanned"] = False
    PD_STATE["safe"] = True
    PD_STATE["threats"] = []

def simulate_pd_remove():
    PD_STATE["active"] = False
    PD_STATE["needs_otp"] = False
    PD_STATE["otp_verified"] = False
    PD_STATE["scanned"] = False
    PD_STATE["safe"] = True
    PD_STATE["threats"] = []

# --- Routes ---

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/pd-status')
def pd_status():
    # Simulate PD insert every 30 seconds for demo
    if int(time.time()) % 60 < 30:
        if not PD_STATE["active"]:
            simulate_pd_insert()
    else:
        if PD_STATE["active"]:
            simulate_pd_remove()
    return jsonify({
        "active": PD_STATE["active"],
        "insert_count": PD_STATE["insert_count"],
        "needs_otp": PD_STATE["needs_otp"]
    })

@app.route('/api/pd-threats')
def pd_threats():
    return jsonify({"threats": PD_STATE["threats"]})

@app.route('/api/pd-scan-status')
def pd_scan_status():
    return jsonify({
        "scanned": PD_STATE["scanned"],
        "safe": PD_STATE["safe"]
    })

@app.route('/api/pd-files')
def pd_files():
    return jsonify({"files": PD_STATE["files"]})

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    if data.get("otp") == PD_STATE["otp"]:
        PD_STATE["otp_verified"] = True
        return jsonify({"verified": True})
    return jsonify({"verified": False})

@app.route('/api/scan-pd', methods=['POST'])
def scan_pd():
    # Simulate scanning: if "virus.exe" is present, mark as unsafe
    threats = []
    for f in PD_STATE["files"]:
        if f["name"].endswith(".exe"):
            threats.append(f"Malware detected: {f['name']}")
    PD_STATE["threats"] = threats
    PD_STATE["scanned"] = True
    PD_STATE["safe"] = len(threats) == 0
    return jsonify({"ok": True})

@app.route('/download-file')
def download_file():
    path = request.args.get('path')
    # For demo, only allow download if safe
    if not PD_STATE["safe"]:
        return "Access Denied: Threats detected.", 403
    # In real app, serve actual files from PD mount point
    # Here, just send a dummy file
    dummy_file = os.path.join(os.path.dirname(__file__), "dummy.txt")
    with open(dummy_file, "w") as f:
        f.write("This is a dummy file for download: " + path)
    return send_file(dummy_file, as_attachment=True, download_name=os.path.basename(path))

if __name__ == '__main__':
    app.run(debug=True)