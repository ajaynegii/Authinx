from app_mongo import app, users_collection, usb_drives_collection, access_logs_collection
from werkzeug.security import generate_password_hash
import pyotp
from datetime import datetime
from pymongo import MongoClient
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def init_mongodb_atlas():
    try:
        # Test connection
        mongodb_uri = os.getenv('MONGODB_URI')
        if not mongodb_uri:
            print("Error: MONGODB_URI not found in .env file")
            return
        
        client = MongoClient(mongodb_uri)
        client.admin.command('ping')
        print("MongoDB Atlas connection successful!")
        
        # Create indexes
        users_collection.create_index('email', unique=True)
        access_logs_collection.create_index('user_id')
        access_logs_collection.create_index('timestamp')
        usb_drives_collection.create_index('user_id')
        
        # Create test user if it doesn't exist
        if not users_collection.find_one({'email': 'test@example.com'}):
            user_data = {
                'email': 'test@example.com',
                'password_hash': generate_password_hash('password123'),
                'otp_secret': pyotp.random_base32(),
                'created_at': datetime.utcnow()
            }
            users_collection.insert_one(user_data)
            print("Created test user")
        else:
            print("Test user already exists")
        
        print("\nMongoDB Atlas database initialized successfully!")
        print("\nTest user credentials:")
        print("Email: test@example.com")
        print("Password: password123")
        print("\nYou can now run the application with: python app_mongo.py")
        
    except Exception as e:
        print(f"Error initializing MongoDB Atlas: {str(e)}")
        print("Please check your MONGODB_URI in the .env file")

if __name__ == '__main__':
    init_mongodb_atlas() 