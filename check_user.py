from app import db, User
from werkzeug.security import generate_password_hash, check_password_hash

def check_user():
    # Get all users
    users = User.query.all()
    print("\n=== Users in Database ===")
    for user in users:
        print(f"Email: {user.email}")
        print(f"Password Hash: {user.password_hash}")
        print(f"OTP Secret: {user.otp_secret}")
        print("---")

    # Test password verification
    test_password = "admin123"
    admin = User.query.filter_by(email="admin@example.com").first()
    if admin:
        print("\n=== Testing Password Verification ===")
        print(f"Test password: {test_password}")
        print(f"Stored hash: {admin.password_hash}")
        is_valid = check_password_hash(admin.password_hash, test_password)
        print(f"Password valid: {is_valid}")

if __name__ == "__main__":
    check_user() 