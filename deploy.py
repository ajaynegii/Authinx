import os
import subprocess
import sys
from waitress import serve
from app import app

def check_requirements():
    """Check if all required packages are installed"""
    try:
        with open('requirements.txt', 'r') as f:
            requirements = f.read().splitlines()
        
        for req in requirements:
            if req:
                package = req.split('==')[0]
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', req])
                print(f"Installed {package}")
    except Exception as e:
        print(f"Error installing requirements: {e}")
        sys.exit(1)

def init_database():
    """Initialize the database"""
    try:
        subprocess.check_call([sys.executable, 'init_db.py'])
        print("Database initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {e}")
        sys.exit(1)

def start_server():
    """Start the production server using Waitress"""
    try:
        print("Starting production server on http://0.0.0.0:8080")
        serve(app, host='0.0.0.0', port=8080, threads=4)
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    print("Starting deployment process...")
    check_requirements()
    init_database()
    print("Starting production server...")
    start_server() 