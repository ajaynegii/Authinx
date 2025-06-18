import os
from dotenv import load_dotenv
from flask import Flask
from flask_mail import Mail, Message

# Load environment variables
load_dotenv()

# Create Flask app for testing
app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)

def test_email():
    try:
        with app.app_context():
            msg = Message('Test Email from Secure USB App',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[app.config['MAIL_USERNAME']])
            msg.body = 'This is a test email to verify your email configuration is working correctly.'
            mail.send(msg)
            print("✅ Test email sent successfully!")
            print(f"Check your inbox: {app.config['MAIL_USERNAME']}")
            return True
    except Exception as e:
        print(f"❌ Email test failed: {str(e)}")
        print("\nPossible issues:")
        print("1. Check if your Gmail app password is correct")
        print("2. Make sure 2-factor authentication is enabled on your Gmail")
        print("3. Check if 'Less secure app access' is enabled (if using regular password)")
        return False

if __name__ == '__main__':
    print("Testing email configuration...")
    print(f"Email: {os.getenv('MAIL_USERNAME')}")
    print(f"Password: {os.getenv('MAIL_PASSWORD')[:4]}...{os.getenv('MAIL_PASSWORD')[-4:]}")
    test_email() 