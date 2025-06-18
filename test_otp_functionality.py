import requests
import json

def test_otp_functionality():
    base_url = "http://127.0.0.1:8080"
    
    print("Testing OTP Functionality...")
    print("=" * 50)
    
    # Test 1: Check if server is running
    try:
        response = requests.get(f"{base_url}/")
        print(f"✅ Server is running (Status: {response.status_code})")
    except Exception as e:
        print(f"❌ Server is not running: {e}")
        return
    
    # Test 2: Test login (you'll need to do this manually in browser)
    print("\n📝 Manual Testing Required:")
    print("1. Open your browser and go to: http://127.0.0.1:8080")
    print("2. Login with test user:")
    print("   - Email: test@example.com")
    print("   - Password: password123")
    print("3. Insert a USB drive or wait for USB detection")
    print("4. Check if OTP form appears")
    print("5. Check your email (negiajay2006@gmail.com) for OTP")
    print("6. Enter the OTP in the form")
    
    print("\n🔍 Debug Information:")
    print("- Check the terminal where app_mongo.py is running for debug messages")
    print("- Look for messages starting with [DEBUG] or [ERROR]")
    print("- Check your spam/junk folder for OTP emails")
    
    print("\n📧 Email Configuration:")
    print("- Email: negiajay2006@gmail.com")
    print("- App Password: rvuf ggyn xvnd fqcm")
    print("- SMTP: smtp.gmail.com:587")

if __name__ == "__main__":
    test_otp_functionality() 