import os
from dotenv import load_dotenv
from pymongo import MongoClient

# Load environment variables
load_dotenv()

def test_mongodb_connection():
    try:
        mongodb_uri = os.getenv('MONGODB_URI')
        print(f"MongoDB URI: {mongodb_uri}")
        
        if not mongodb_uri:
            print("Error: MONGODB_URI not found in .env file")
            return False
        
        # Test connection
        client = MongoClient(mongodb_uri)
        client.admin.command('ping')
        print("✅ MongoDB Atlas connection successful!")
        
        # List databases
        databases = client.list_database_names()
        print(f"Available databases: {databases}")
        
        # Test database access
        db = client['secure_usb']
        collections = db.list_collection_names()
        print(f"Collections in secure_usb: {collections}")
        
        client.close()
        return True
        
    except Exception as e:
        print(f"❌ MongoDB connection failed: {str(e)}")
        print("\nPlease check your MongoDB Atlas connection string.")
        print("The format should be:")
        print("mongodb+srv://username:password@cluster-name.xxxxx.mongodb.net/database?retryWrites=true&w=majority")
        return False

if __name__ == '__main__':
    test_mongodb_connection() 