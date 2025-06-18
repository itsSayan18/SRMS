from app import app
import sys
import os

try:
    print("Starting the Student Record Management System...")
    
    # Get host and port from environment variables (for cloud hosting)
    host = os.getenv('HOST', '127.0.0.1')
    port = int(os.getenv('PORT', 5001))
    
    print(f"Access the application at: http://{host}:{port}")
    app.run(host=host, port=port, debug=False)  # Set debug=False for production
except Exception as e:
    print(f"Error starting the application: {e}", file=sys.stderr)
    sys.exit(1) 