from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import pyotp
import json
from pymongo import MongoClient
from bson.objectid import ObjectId
from dotenv import load_dotenv
import subprocess
import mimetypes
from werkzeug.utils import secure_filename
import random
import pytz

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Custom Jinja2 filter to convert UTC to IST
@app.template_filter('utc_to_ist')
def utc_to_ist(timestamp):
    """Convert UTC timestamp to IST"""
    if timestamp is None:
        return 'Never'
    
    # Create UTC timezone object
    utc_tz = pytz.UTC
    # Create IST timezone object
    ist_tz = pytz.timezone('Asia/Kolkata')
    
    # If timestamp is naive (no timezone), assume it's UTC
    if timestamp.tzinfo is None:
        timestamp = utc_tz.localize(timestamp)
    
    # Convert to IST
    ist_time = timestamp.astimezone(ist_tz)
    return ist_time.strftime('%Y-%m-%d %H:%M:%S')

def convert_utc_to_ist(timestamp):
    """Helper function to convert UTC timestamp to IST string"""
    if timestamp is None:
        return 'Never'
    
    # Create UTC timezone object
    utc_tz = pytz.UTC
    # Create IST timezone object
    ist_tz = pytz.timezone('Asia/Kolkata')
    
    # If timestamp is naive (no timezone), assume it's UTC
    if timestamp.tzinfo is None:
        timestamp = utc_tz.localize(timestamp)
    
    # Convert to IST
    ist_time = timestamp.astimezone(ist_tz)
    return ist_time.strftime('%Y-%m-%d %H:%M:%S')

# MongoDB configuration
try:
    mongodb_uri = os.getenv('MONGODB_URI')
    if not mongodb_uri:
        raise ValueError("MONGODB_URI not found in environment variables")
    client = MongoClient(mongodb_uri)
    # Test the connection
    client.admin.command('ping')
    db = client['secure_usb']
    users_collection = db['users']
    usb_drives_collection = db['usb_drives']
    access_logs_collection = db['access_logs']
    print("MongoDB Atlas connected successfully!")
except Exception as e:
    print(f"MongoDB connection failed: {str(e)}")
    print("Please check your MONGODB_URI in the .env file")
    print("Make sure you have a valid MongoDB Atlas connection string")
    exit(1)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data.get('_id', 'demo_id'))
        self.email = user_data['email']
        self.password_hash = user_data['password_hash']
        self.otp_secret = user_data['otp_secret']
        self.created_at = user_data.get('created_at', datetime.utcnow())

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = users_collection.find_one({'_id': ObjectId(user_id)})
        if user_data:
            return User(user_data)
    except Exception as e:
        print(f"Error loading user: {str(e)}")
    return None

def send_otp_email(user_email, otp):
    msg = Message('Your OTP Code',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user_email])
    msg.body = f'Your OTP code is: {otp}'
    mail.send(msg)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if users_collection.find_one({'email': email}):
            flash('Email already registered')
            return redirect(url_for('register'))
        
        user_data = {
            'email': email,
            'password_hash': generate_password_hash(password),
            'otp_secret': pyotp.random_base32(),
            'created_at': datetime.utcnow()
        }
        
        users_collection.insert_one(user_data)
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user_data = users_collection.find_one({'email': email})
        if user_data and User(user_data).check_password(password):
            user = User(user_data)
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp = request.form['otp']
        user = User.get(session['user_id'])
        
        if pyotp.TOTP(user.otp_secret).verify(otp):
            login_user(user)
            users_collection.update_one(
                {'_id': ObjectId(user.id)},
                {'$set': {'last_login': datetime.utcnow()}}
            )
            return redirect(url_for('dashboard'))
        
        flash('Invalid OTP')
    return render_template('verify_otp.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Only get recent access logs, do not fetch or render user_drives
        recent_logs = list(access_logs_collection.find(
            {'user_id': current_user.id}
        ).sort('timestamp', -1).limit(10))
        return render_template('dashboard.html', recent_logs=recent_logs)
    except Exception as e:
        print(f"Dashboard error: {str(e)}")  # For debugging
        flash('Error loading dashboard')
        return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if users_collection.find_one({'email': email}):
            flash('Email already registered')
            return redirect(url_for('signup'))
        
        password_hash = generate_password_hash(password)
        otp_secret = pyotp.random_base32()
        
        users_collection.insert_one({
            'email': email,
            'password_hash': password_hash,
            'otp_secret': otp_secret,
            'created_at': datetime.utcnow()
        })
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/drive/<drive_id>')
@login_required
def view_drive(drive_id):
    try:
        drive = usb_drives_collection.find_one({
            '_id': ObjectId(drive_id),
            'user_id': current_user.id
        })
        
        if not drive:
            flash('Drive not found')
            return redirect(url_for('dashboard'))
            
        # Get drive access logs
        drive_logs = list(access_logs_collection.find({
            'drive_id': drive_id
        }).sort('timestamp', -1).limit(20))
        
        return render_template('view_drive.html', 
                             drive=drive,
                             logs=drive_logs)
    except Exception as e:
        print(f"View drive error: {str(e)}")
        flash('Error viewing drive')
        return redirect(url_for('dashboard'))

def detect_usb_drives():
    """Detect connected USB drives on Windows"""
    try:
        # Use PowerShell to get removable drives
        cmd = "Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq 2} | Select-Object DeviceID"
        result = subprocess.run(['powershell', '-Command', cmd], capture_output=True, text=True)
        
        drives = []
        for line in result.stdout.split('\n'):
            if ':' in line:
                drive = line.strip()
                if os.path.exists(drive):
                    drives.append(drive)
        return drives
    except Exception as e:
        print(f"Error detecting USB drives: {str(e)}")
        return []

def scan_drive(drive_path):
    """Scan drive for malware using ClamAV"""
    try:
        # Check if ClamAV is installed
        clamd_path = r"C:\Program Files\ClamAV\clamd.exe"
        if not os.path.exists(clamd_path):
            return {'safe': True, 'message': 'ClamAV not installed, skipping scan'}
        
        # Run ClamAV scan
        cmd = f'"{clamd_path}" --scan "{drive_path}"'
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Check if any malware was found
        if 'FOUND' in result.stdout:
            return {'safe': False, 'message': 'Malware detected'}
        return {'safe': True, 'message': 'Scan completed, no threats found'}
    except Exception as e:
        print(f"Error scanning drive: {str(e)}")
        return {'safe': False, 'message': 'Error during scan'}

@app.route('/check-usb')
@login_required
def check_usb():
    """Check for connected USB drives"""
    drives = detect_usb_drives()
    return jsonify({
        'detected': len(drives) > 0,
        'drive_path': drives[0] if drives else 'No USB drive detected'
    })

@app.route('/verify-usb', methods=['POST'])
@login_required
def verify_usb():
    """Send automatic OTP for USB verification (only once per session)"""
    try:
        # Check if automatic OTP was already sent in this session
        if session.get('auto_otp_sent'):
            return jsonify({'success': True, 'message': 'OTP already sent automatically', 'otp_already_sent': True})

        # Generate random 6-digit OTP
        otp = str(random.randint(100000, 999999))
        print(f"[DEBUG] Automatic OTP for {current_user.email}: {otp}")  # Print OTP for testing

        # Send OTP via email
        msg = Message('USB Drive Verification OTP',
                     sender=app.config['MAIL_USERNAME'],
                     recipients=[current_user.email])
        msg.body = f'Your OTP for USB drive verification is: {otp}'
        try:
            mail.send(msg)
            print(f"[DEBUG] Automatic OTP email sent to {current_user.email}")
        except Exception as mail_error:
            import traceback
            print(f"[ERROR] Failed to send automatic OTP email: {mail_error}")
            traceback.print_exc()
            return jsonify({'success': False, 'message': f'Error sending OTP: {mail_error}'})

        # Store OTP in session and mark automatic OTP as sent
        session['usb_otp'] = otp
        session['otp_time'] = datetime.utcnow().timestamp()
        session['auto_otp_sent'] = True

        return jsonify({'success': True, 'message': 'OTP sent automatically', 'otp_already_sent': False})
    except Exception as e:
        import traceback
        print(f"[ERROR] Unexpected error in verify_usb: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Unexpected error: {e}'})

@app.route('/verify-usb-otp', methods=['POST'])
@login_required
def verify_usb_otp():
    """Verify OTP for USB access"""
    try:
        data = request.get_json()
        otp = data.get('otp')
        # Check if OTP exists and is not expired (5 minutes)
        stored_otp = session.get('usb_otp')
        otp_time = session.get('otp_time')
        if not stored_otp or not otp_time:
            # Log denied attempt
            access_logs_collection.insert_one({
                'user_id': current_user.id,
                'action': 'OTP_VERIFY',
                'details': 'No OTP found',
                'timestamp': datetime.utcnow(),
                'status': 'Denied'
            })
            return jsonify({'success': False, 'message': 'No OTP found'})
        if datetime.utcnow().timestamp() - otp_time > 300:  # 5 minutes
            # Log denied attempt
            access_logs_collection.insert_one({
                'user_id': current_user.id,
                'action': 'OTP_VERIFY',
                'details': 'OTP expired',
                'timestamp': datetime.utcnow(),
                'status': 'Denied'
            })
            return jsonify({'success': False, 'message': 'OTP expired'})
        if otp != stored_otp:
            # Log denied attempt
            access_logs_collection.insert_one({
                'user_id': current_user.id,
                'action': 'OTP_VERIFY',
                'details': 'Invalid OTP',
                'timestamp': datetime.utcnow(),
                'status': 'Denied'
            })
            return jsonify({'success': False, 'message': 'Invalid OTP'})
        # Clear OTP from session
        session.pop('usb_otp', None)
        session.pop('otp_time', None)
        # Log granted attempt
        access_logs_collection.insert_one({
            'user_id': current_user.id,
            'action': 'OTP_VERIFY',
            'details': 'OTP verified. Access granted.',
            'timestamp': datetime.utcnow(),
            'status': 'Granted'
        })
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error verifying OTP: {str(e)}")
        access_logs_collection.insert_one({
            'user_id': current_user.id,
            'action': 'OTP_VERIFY',
            'details': f'Error verifying OTP: {str(e)}',
            'timestamp': datetime.utcnow(),
            'status': 'Denied'
        })
        return jsonify({'success': False, 'message': 'Error verifying OTP'})

@app.route('/scan-usb', methods=['POST'])
@login_required
def scan_usb():
    """Scan USB drive for malware"""
    drives = detect_usb_drives()
    if not drives:
        return jsonify({'safe': False, 'message': 'No USB drive detected'})
    
    drive_path = drives[0]
    scan_result = scan_drive(drive_path)
    
    # Log the scan result
    access_logs_collection.insert_one({
        'user_id': current_user.id,
        'drive_path': drive_path,
        'action': 'SCAN',
        'details': scan_result['message'],
        'timestamp': datetime.utcnow()
    })
    
    return jsonify(scan_result)

@app.route('/list-files')
@login_required
def list_files():
    """List files in a directory"""
    path = request.args.get('path', '')
    if not path:
        drives = detect_usb_drives()
        if not drives:
            return jsonify({'error': 'No USB drive detected'})
        path = drives[0]
    
    try:
        files = []
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            try:
                stat = os.stat(full_path)
                files.append({
                    'name': item,
                    'path': full_path,
                    'is_dir': os.path.isdir(full_path),
                    'size': f"{stat.st_size / 1024:.1f} KB" if not os.path.isdir(full_path) else '',
                    'type': mimetypes.guess_type(full_path)[0] or 'Unknown',
                    'modified': convert_utc_to_ist(datetime.fromtimestamp(stat.st_mtime))
                })
            except Exception as e:
                print(f"Error getting file info for {full_path}: {str(e)}")
        
        return jsonify({'files': files})
    except Exception as e:
        print(f"Error listing files: {str(e)}")
        return jsonify({'error': 'Error listing files'})

@app.route('/download-file')
@login_required
def download_file():
    """Download a file"""
    path = request.args.get('path', '')
    if not path or not os.path.exists(path):
        return jsonify({'error': 'File not found'})
    
    try:
        return send_file(
            path,
            as_attachment=True,
            download_name=os.path.basename(path)
        )
    except Exception as e:
        print(f"Error downloading file: {str(e)}")
        return jsonify({'error': 'Error downloading file'})

# --- API for Professional Dashboard ---

@app.route('/api/pd-status')
@login_required
def api_pd_status():
    # Check for connected USB drives
    drives = detect_usb_drives()
    # Count insertions (could be tracked in DB, here just example)
    insert_count = usb_drives_collection.count_documents({'user_id': current_user.id})
    # Needs OTP if drive detected and not yet verified
    needs_otp = bool(drives)
    # --- Reset session flag if USB is removed ---
    if not drives:
        session.pop('auto_otp_sent', None)
        session.pop('usb_otp', None)
        session.pop('otp_time', None)
    return jsonify({
        'active': bool(drives),
        'insert_count': insert_count,
        'needs_otp': needs_otp
    })

@app.route('/api/pd-threats')
@login_required
def api_pd_threats():
    # Get recent threats for this user (malware scan logs)
    logs = access_logs_collection.find({
        'user_id': current_user.id,
        'action': 'SCAN',
        'details': {'$regex': 'Malware|threat|virus', '$options': 'i'}
    }).sort('timestamp', -1).limit(10)
    threats = [log['details'] for log in logs]
    return jsonify({'threats': threats})

@app.route('/api/pd-scan-status')
@login_required
def api_pd_scan_status():
    # Get last scan result for this user
    log = access_logs_collection.find_one({
        'user_id': current_user.id,
        'action': 'SCAN'
    }, sort=[('timestamp', -1)])
    if log:
        safe = 'no threats' in log['details'].lower() or 'no virus' in log['details'].lower()
        return jsonify({'scanned': True, 'safe': safe})
    return jsonify({'scanned': False, 'safe': None})

@app.route('/api/pd-files')
@login_required
def api_pd_files():
    # Only allow if last scan was safe
    log = access_logs_collection.find_one({
        'user_id': current_user.id,
        'action': 'SCAN'
    }, sort=[('timestamp', -1)])
    if not log or not ('no threats' in log['details'].lower() or 'no virus' in log['details'].lower()):
        return jsonify({'files': []})
    # List files on the first detected USB drive
    drives = detect_usb_drives()
    if not drives:
        return jsonify({'files': []})
    path = drives[0]
    files = []
    for item in os.listdir(path):
        full_path = os.path.join(path, item)
        try:
            stat = os.stat(full_path)
            files.append({
                'name': item,
                'path': full_path,
                'type': 'directory' if os.path.isdir(full_path) else 'file',
                'size': f"{stat.st_size / 1024:.1f} KB" if not os.path.isdir(full_path) else '',
                'modified': convert_utc_to_ist(datetime.fromtimestamp(stat.st_mtime))
            })
        except Exception:
            continue
    return jsonify({'files': files})

@app.route('/api/verify-otp', methods=['POST'])
@login_required
def api_verify_otp():
    data = request.get_json()
    otp = data.get('otp')
    # Check OTP for current user
    if pyotp.TOTP(current_user.otp_secret).verify(otp):
        return jsonify({'verified': True})
    return jsonify({'verified': False})

@app.route('/api/scan-pd', methods=['POST'])
@login_required
def api_scan_pd():
    # Scan the first detected USB drive
    drives = detect_usb_drives()
    if not drives:
        return jsonify({'safe': False, 'message': 'No USB drive detected'})
    drive_path = drives[0]
    scan_result = scan_drive(drive_path)
    # Log the scan result
    access_logs_collection.insert_one({
        'user_id': current_user.id,
        'drive_path': drive_path,
        'action': 'SCAN',
        'details': scan_result['message'],
        'timestamp': datetime.utcnow()
    })
    return jsonify(scan_result)

@app.route('/api/access-history')
@login_required
def api_access_history():
    # Fetch all access logs for this user
    logs = access_logs_collection.find({'user_id': current_user.id}).sort('timestamp', -1)
    history = []
    for log in logs:
        ts = log.get('timestamp')
        if isinstance(ts, datetime):
            timestamp_str = convert_utc_to_ist(ts)
            # Get day from IST time
            utc_tz = pytz.UTC
            ist_tz = pytz.timezone('Asia/Kolkata')
            if ts.tzinfo is None:
                ts = utc_tz.localize(ts)
            ist_time = ts.astimezone(ist_tz)
            day_str = ist_time.strftime('%A')
        else:
            timestamp_str = str(ts)
            day_str = '-'
        status = 'Granted' if ('granted' in log.get('details', '').lower() or 'no threats' in log.get('details', '').lower() or 'no virus' in log.get('details', '').lower()) else 'Denied'
        history.append({
            'timestamp': timestamp_str,
            'day': day_str,
            'drive_name': log.get('drive_path', log.get('drive_name', '-')),
            'serial_number': log.get('serial_number', '-'),
            'status': status,
            'details': log.get('details', '-')
        })
    return jsonify({'history': history})

if __name__ == '__main__':
    app.config['DEBUG'] = True
    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.run(host='0.0.0.0', port=8080, debug=False)