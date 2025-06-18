# Deployment Guide for Secure USB Access Control System

## Deploying to PythonAnywhere

### 1. Sign Up for PythonAnywhere
1. Go to [PythonAnywhere](https://www.pythonanywhere.com/)
2. Sign up for a free account
3. Log in to your dashboard

### 2. Upload Your Code
1. In the PythonAnywhere dashboard, go to the "Files" tab
2. Create a new directory for your project (e.g., `secure_usb`)
3. Upload all your project files to this directory:
   - app.py
   - wsgi.py
   - requirements.txt
   - templates/ (folder)
   - static/ (folder if you have any)

### 3. Set Up a Virtual Environment
1. Go to the "Consoles" tab
2. Start a new Bash console
3. Run these commands:
```bash
cd secure_usb
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Configure the Web App
1. Go to the "Web" tab
2. Click "Add a new web app"
3. Choose "Manual configuration"
4. Select Python 3.8
5. In the "Code" section:
   - Set the source code directory to `/home/YOUR_USERNAME/secure_usb`
   - Set the working directory to `/home/YOUR_USERNAME/secure_usb`
   - Set the WSGI configuration file to `/var/www/YOUR_USERNAME_pythonanywhere_com_wsgi.py`

### 5. Configure WSGI File
1. Click on the WSGI configuration file link
2. Replace its contents with:
```python
import sys
path = '/home/YOUR_USERNAME/secure_usb'
if path not in sys.path:
    sys.path.append(path)

from app import app as application
```

### 6. Set Environment Variables
1. In the "Web" tab, go to "Environment variables"
2. Add these variables:
```
SECRET_KEY=your-secret-key-here
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
DATABASE_URL=sqlite:///secure_usb.db
```

### 7. Initialize the Database
1. Go to the "Consoles" tab
2. Start a new Bash console
3. Run:
```bash
cd secure_usb
source venv/bin/activate
python init_db.py
```

### 8. Restart the Web App
1. Go to the "Web" tab
2. Click the "Reload" button

Your app should now be live at: `YOUR_USERNAME.pythonanywhere.com`

## Security Considerations
1. Use HTTPS (PythonAnywhere provides this by default)
2. Set strong passwords
3. Keep your secret key secure
4. Regularly update dependencies
5. Monitor access logs

## Troubleshooting
- Check the error logs in the "Web" tab
- Verify all environment variables are set correctly
- Ensure the database is initialized
- Check file permissions

## Maintenance
1. Regular backups of the database
2. Monitor system logs
3. Update dependencies regularly
4. Check for security updates 