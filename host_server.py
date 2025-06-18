from waitress import serve
from app import app

if __name__ == '__main__':
    print("Starting production server on http://0.0.0.0:8080")
    print("You can access the application at:")
    print("- Local: http://localhost:8080")
    print("- Network: http://<your-ip-address>:8080")
    serve(app, host='0.0.0.0', port=8080, threads=4) 