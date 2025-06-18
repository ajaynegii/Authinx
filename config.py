import os
from dotenv import load_dotenv

load_dotenv()

class ProductionConfig:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    # MongoDB Atlas configuration
    MONGODB_URI = os.getenv('MONGODB_URI')
    
    # Email configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    
    # Security settings
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    
    # ClamAV configuration
    CLAMAV_HOST = 'localhost'
    CLAMAV_PORT = 3310 