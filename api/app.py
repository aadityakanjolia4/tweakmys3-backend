from flask import Flask, request, jsonify, session
from flask_cors import CORS
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import re
import os
import json
from urllib.parse import urlparse
import logging
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-change-this')

# Enable CORS for all routes - comprehensive configuration for development
CORS(app, supports_credentials=True)
    #  resources={
    #      r"/api/*": {
    #          "origins": "*",
    #          "methods": ["GET", "POST", "OPTIONS"],
    #          "allow_headers": ["Content-Type", "Authorization", "Access-Control-Allow-Origin"],
    #          "supports_credentials": False
    #      },
    #      r"/health": {
    #          "origins": "*",
    #          "methods": ["GET", "OPTIONS"]
    #      }
    #  })

# Initialize S3 client
try:
    s3_client = boto3.client('s3')
    logger.info("S3 client initialized successfully")
except NoCredentialsError:
    logger.error("AWS credentials not found. Please configure your AWS credentials.")
    s3_client = None

# @app.after_request
# def after_request(response):
#     """Add CORS headers to all responses"""
#     response.headers.add('Access-Control-Allow-Origin', '*')
#     response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With')
#     response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS,PUT,DELETE')
#     response.headers.add('Access-Control-Allow-Credentials', 'false')
#     return response

def check_credentials(username, password):
    """Check if provided credentials match environment variables"""
    expected_username = os.getenv('APP_USERNAME')
    expected_password = os.getenv('APP_PASSWORD')
    
    if not expected_username or not expected_password:
        logger.error("APP_USERNAME and APP_PASSWORD environment variables not set")
        return False
    
    return username == expected_username and password == expected_password

def require_auth(f):
    """Decorator to require authentication for protected routes"""
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def parse_s3_url(s3_url):
    """
    Parse S3 URL to extract bucket name and object key
    Supports multiple S3 URL formats:
    - s3://bucket-name/key (S3 URI format)
    - https://bucket-name.s3.region.amazonaws.com/key (Virtual-hosted-style)
    - https://s3.region.amazonaws.com/bucket-name/key (Path-style)
    """
    try:
        parsed = urlparse(s3_url)
        
        # S3 URI format: s3://bucket-name/key
        if parsed.scheme == 's3':
            bucket_name = parsed.netloc
            object_key = parsed.path.lstrip('/')
            if bucket_name and object_key:
                return bucket_name, object_key
        
        # Virtual-hosted-style URL: https://bucket-name.s3.region.amazonaws.com/key
        elif '.s3.' in parsed.netloc and 'amazonaws.com' in parsed.netloc:
            bucket_name = parsed.netloc.split('.s3.')[0]
            object_key = parsed.path.lstrip('/')
            return bucket_name, object_key
        
        # Path-style URL: https://s3.region.amazonaws.com/bucket-name/key
        elif 's3.' in parsed.netloc and 'amazonaws.com' in parsed.netloc:
            path_parts = parsed.path.lstrip('/').split('/', 1)
            if len(path_parts) >= 2:
                bucket_name = path_parts[0]
                object_key = path_parts[1]
                return bucket_name, object_key
        
        # Legacy path-style: https://s3.amazonaws.com/bucket-name/key
        elif parsed.netloc == 's3.amazonaws.com':
            path_parts = parsed.path.lstrip('/').split('/', 1)
            if len(path_parts) >= 2:
                bucket_name = path_parts[0]
                object_key = path_parts[1]
                return bucket_name, object_key
        
        return None, None
    
    except Exception as e:
        logger.error(f"Error parsing S3 URL: {str(e)}")
        return None, None



@app.route('/api/login', methods=['POST'])
def login():
    """Login endpoint to authenticate user"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        if check_credentials(username, password):
            session['authenticated'] = True
            session['username'] = username
            logger.info(f"User {username} logged in successfully")
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'username': username
            })
        else:
            logger.warning(f"Failed login attempt for username: {username}")
            return jsonify({'error': 'Invalid username or password'}), 401
    
    except Exception as e:
        logger.error(f"Error in login endpoint: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout endpoint"""
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/auth-status', methods=['GET'])
def auth_status():
    """Check authentication status"""
    return jsonify({
        'authenticated': session.get('authenticated', False),
        'username': session.get('username', None)
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'S3 JSON Viewer API is running',
        's3_client_available': s3_client is not None,
        'cors': 'enabled',
        'auth_required': True
    })

@app.route('/test-cors', methods=['GET', 'POST'])
def test_cors():
    """Simple CORS test endpoint"""
    return jsonify({
        'message': 'CORS is working!',
        'method': request.method,
        'origin': request.headers.get('Origin', 'No origin header'),
        'timestamp': str(datetime.now()) if 'datetime' in globals() else 'N/A'
    })

@app.route('/api/get-json', methods=['POST']) 
@require_auth
def get_json_endpoint():
    """
    Fetch JSON directly from S3 and return to frontend (bypasses CORS)
    Expected JSON payload: {"s3_url": "s3://bucket/key"}
    """
    try:
        # Validate request
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        data = request.get_json()
        s3_url = data.get('s3_url')
        
        if not s3_url:
            return jsonify({'error': 'Missing s3_url parameter'}), 400
        
        # Parse S3 URL
        bucket_name, object_key = parse_s3_url(s3_url)
        
        if not bucket_name or not object_key:
            return jsonify({
                'error': 'Invalid S3 URL format. Please provide a valid S3 URL.',
                'examples': [
                    's3://bucket-name/path/to/file.json',
                    'https://bucket-name.s3.amazonaws.com/path/to/file.json'
                ]
            }), 400
        
        # Get object directly using boto3 (bypasses CORS)
        if not s3_client:
            return jsonify({'error': 'S3 client not available. Check AWS credentials.'}), 500
        
        try:
            response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
            content = response['Body'].read().decode('utf-8')
            
            # Try to parse as JSON to validate
            import json
            json_data = json.loads(content)
            
            logger.info(f"Successfully retrieved JSON from s3://{bucket_name}/{object_key}")

            string_beautify = False
            if "data" in json_data and "response" in json_data["data"]:
                ans = json_data["data"]["response"]
                ans = json.loads(ans)
                json_data["data"]["response"] = ans
                string_beautify = True

            return jsonify({
                'success': True,
                'json_data': json_data,
                'bucket': bucket_name,
                'key': object_key,
                'content_type': response.get('ContentType', 'application/json'),
                'last_modified': response.get('LastModified').isoformat() if response.get('LastModified') else None,
                'size': response.get('ContentLength', 0),
                'string_beautify' : string_beautify
            })
        
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchKey':
                return jsonify({'error': f"File not found: s3://{bucket_name}/{object_key}"}), 404
            elif error_code == 'AccessDenied':
                return jsonify({'error': f"Access denied to file: s3://{bucket_name}/{object_key}"}), 403
            else:
                return jsonify({'error': f"AWS Error: {str(e)}"}), 500
        
        except json.JSONDecodeError as e:
            return jsonify({'error': f"Invalid JSON format: {str(e)}"}), 400
    
    except Exception as e:
        logger.error(f"Error in get_json_endpoint: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500





@app.route('/api/save-json', methods=['POST'])
@require_auth
def save_json_endpoint():
    """
    Save JSON data back to S3
    Expected JSON payload: {
        "s3_url": "s3://bucket/key", 
        "json_data": {...}
    }
    """
    logger.info("🔧 DEBUG: save_json_endpoint called")
    try:
        # Validate request
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        data = request.get_json()
        logger.info(f"🔧 DEBUG: Request data keys: {list(data.keys()) if data else 'None'}")
        
        s3_url = data.get('s3_url')
        json_data = data.get('json_data')
        string_beautify = data.get('string_beautify', False)

        logger.info(f"🔧 DEBUG: s3_url = {s3_url}")
        logger.info(f"🔧 DEBUG: json_data type = {type(json_data)}")
        
        if not s3_url:
            logger.warning("❌ DEBUG: Missing s3_url parameter")
            return jsonify({'error': 'Missing s3_url parameter'}), 400
            
        if json_data is None:
            logger.warning("❌ DEBUG: Missing json_data parameter")
            return jsonify({'error': 'Missing json_data parameter'}), 400
        
        # Parse S3 URL
        bucket_name, object_key = parse_s3_url(s3_url)
        
        if not bucket_name or not object_key:
            return jsonify({
                'error': 'Invalid S3 URL format. Please provide a valid S3 URL.',
                'examples': [
                    's3://bucket-name/path/to/file.json',
                    'https://bucket-name.s3.amazonaws.com/path/to/file.json'
                ]
            }), 400
        
        # Check S3 client
        if not s3_client:
            return jsonify({'error': 'S3 client not available. Check AWS credentials.'}), 500
        
        try:
            # Convert JSON data to string with proper formatting
            if string_beautify:
                ans = json_data["data"]["response"]
                ans = json.dumps(ans, indent=2)
                json_data["data"]["response"] = ans
            json_string = json.dumps(json_data, indent=2, ensure_ascii=False)
            # Save to S3
            response = s3_client.put_object(
                Bucket=bucket_name,
                Key=object_key,
                Body=json_string.encode('utf-8'),
                ContentType='application/json',
                ServerSideEncryption='AES256'  # Optional: encrypt at rest
            )
            
            logger.info(f"Successfully saved JSON to s3://{bucket_name}/{object_key}")
            
            return jsonify({
                'success': True,
                'message': 'JSON saved successfully to S3',
                'bucket': bucket_name,
                'key': object_key,
                's3_url': s3_url,
                'size': len(json_string.encode('utf-8')),
                'etag': response.get('ETag', '').strip('"'),
                'last_modified': datetime.now().isoformat()
            })
        
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDenied':
                return jsonify({
                    'error': f"Access denied: You don't have permission to write to s3://{bucket_name}/{object_key}. Check your AWS credentials and bucket permissions."
                }), 403
            elif error_code == 'NoSuchBucket':
                return jsonify({
                    'error': f"Bucket not found: {bucket_name} does not exist."
                }), 404
            else:
                return jsonify({
                    'error': f"AWS Error: {str(e)}"
                }), 500
        
        except Exception as save_error:
            return jsonify({
                'error': f"Failed to save JSON: {str(save_error)}"
            }), 500
    
    except Exception as e:
        logger.error(f"Error in save_json_endpoint: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/get-json', methods=['OPTIONS'])
@app.route('/api/save-json', methods=['OPTIONS'])
@app.route('/api/login', methods=['OPTIONS'])
@app.route('/api/logout', methods=['OPTIONS'])
@app.route('/api/auth-status', methods=['OPTIONS'])
@app.route('/health', methods=['OPTIONS'])
@app.route('/test-cors', methods=['OPTIONS'])
def handle_options():
    """Handle preflight OPTIONS requests"""
    return jsonify({'status': 'OK'})

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 