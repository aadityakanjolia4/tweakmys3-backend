from flask import Flask, request, jsonify
from flask_cors import CORS
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import re
import os
import json
from urllib.parse import urlparse
import logging
from datetime import datetime, timedelta
from dotenv import load_dotenv
import jwt

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-change-this')

# JWT Configuration
JWT_SECRET_KEY = app.secret_key  # Use same key or separate
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 1  # Token expires in 1 hour

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

# --- JWT Token Functions ---
def create_token(username):
    """Generate JWT token for authenticated user"""
    payload = {
        "user": username,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.utcnow()  # Issued at time
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_token(token):
    """Verify JWT token and return username if valid"""
    try:
        decoded = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return decoded.get("user")
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {str(e)}")
        return None

def get_current_user():
    """Get current user from Authorization header"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    
    token = auth_header.split(" ")[1]
    return verify_token(token)

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
    """Login endpoint to authenticate user and return JWT token"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        if check_credentials(username, password):
            token = create_token(username)
            logger.info(f"User {username} logged in successfully")
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'username': username,
                'token': token
            })
        else:
            logger.warning(f"Failed login attempt for username: {username}")
            return jsonify({'error': 'Invalid username or password'}), 401
    
    except Exception as e:
        logger.error(f"Error in login endpoint: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout endpoint - JWT tokens are stateless, client should discard token"""
    # With JWT, logout is handled client-side by removing the token
    # No server-side session to clear
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/auth-status', methods=['GET'])
def auth_status():
    """Check authentication status using JWT token"""
    user = get_current_user()
    return jsonify({
        'authenticated': user is not None,
        'username': user if user else None
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
def get_json_endpoint():
    """
    Fetch JSON directly from S3 and return to frontend (bypasses CORS)
    Expected JSON payload: {"s3_url": "s3://bucket/key"}
    """
    # Check authentication using JWT token
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

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

            # First try JSON
            def looks_like_markdown(text):
                try:
                    if not isinstance(text, str):
                        return False
                    md_indicators = [
                        r"^# +",           # headings
                        r"\*\*.+\*\*",   # bold
                        r"[_*].+[_*]",     # italic
                        r"```[\s\S]*?```", # code fences
                        r"^- ",            # bullets
                        r"^\d+\. ",      # numbered list
                        r"\[.+\]\(.+\)", # links
                        r"^> ",            # blockquote
                    ]
                    import re
                    for pat in md_indicators:
                        if re.search(pat, text, flags=re.MULTILINE):
                            return True
                    return False
                except Exception:
                    return False

            try:
                import json
                json_data = json.loads(content)

                logger.info(f"Successfully retrieved JSON from s3://{bucket_name}/{object_key}")

                string_beautify = False
                response_is_markdown = False
                if "data" in json_data and "response" in json_data.get("data", {}):
                    ans = json_data["data"]["response"]
                    # If nested response is a JSON string, parse it
                    try:
                        parsed_ans = json.loads(ans)
                        json_data["data"]["response"] = parsed_ans
                        string_beautify = True
                    except Exception:
                        # Not JSON. Check if markdown-like
                        if looks_like_markdown(ans):
                            response_is_markdown = True

                return jsonify({
                    'success': True,
                    'data_type': 'json',
                    'json_data': json_data,
                    'response_is_markdown': response_is_markdown,
                    'bucket': bucket_name,
                    'key': object_key,
                    'content_type': response.get('ContentType', 'application/json'),
                    'last_modified': response.get('LastModified').isoformat() if response.get('LastModified') else None,
                    'size': response.get('ContentLength', 0),
                    'string_beautify': string_beautify
                })
            except Exception:
                # Not JSON - treat as text/markdown
                logger.info(f"Non-JSON content from s3://{bucket_name}/{object_key}; returning as text/markdown")
                return jsonify({
                    'success': True,
                    'data_type': 'markdown',
                    'text_content': content,
                    'bucket': bucket_name,
                    'key': object_key,
                    'content_type': response.get('ContentType', 'text/plain'),
                    'last_modified': response.get('LastModified').isoformat() if response.get('LastModified') else None,
                    'size': response.get('ContentLength', 0)
                })

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchKey':
                return jsonify({'error': f"File not found: s3://{bucket_name}/{object_key}"}), 404
            elif error_code == 'AccessDenied':
                return jsonify({'error': f"Access denied to file: s3://{bucket_name}/{object_key}"}), 403
            else:
                return jsonify({'error': f"AWS Error: {str(e)}"}), 500
        
    
    except Exception as e:
        logger.error(f"Error in get_json_endpoint: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500





@app.route('/api/save-json', methods=['POST'])
def save_json_endpoint():
    """
    Save JSON data back to S3
    Expected JSON payload: {
        "s3_url": "s3://bucket/key", 
        "json_data": {...}
    }
    """
    # Check authentication using JWT token
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

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
    app.run(debug=True, host='0.0.0.0', port=4000) 