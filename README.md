# Secure USB Drive Access Control System

A comprehensive system for secure USB drive access with malware scanning, OTP authentication, and activity logging.

## Features

- USB drive malware scanning using ClamAV
- OTP-based authentication via email
- Web interface for file browsing
- Real-time threat alerts
- Comprehensive activity logging
- Secure file access control

## Setup Instructions

1. Install Python 3.8 or higher
2. Install ClamAV antivirus engine
3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Configure environment variables in `.env` file
6. Initialize the database:
   ```bash
   python init_db.py
   ```
7. Run the application:
   ```bash
   python app.py
   ```

## Security Features

- Real-time malware scanning
- Two-factor authentication (OTP)
- Secure session management
- Activity logging and monitoring
- File access control
- Threat alerts

## Environment Variables

Create a `.env` file with the following variables:
```
SECRET_KEY=your_secret_key
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
DATABASE_URL=sqlite:///secure_usb.db
``` 