from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import uuid
from datetime import datetime, timedelta
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import re
import logging
from urllib.parse import urlparse
from collections import defaultdict
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['DATABASE'] = 'backend/garagesale.db'

# ============================================================================
# USER CONFIGURATION - Edit these values to customize your setup
# ============================================================================

# Admin section network restrictions
# Set to True to restrict admin access to RFC1918 private networks only
# Set to False to allow admin access from any IP (relies on password auth)
REQUIRE_PRIVATE_NETWORK = True

# Rate limiting configuration (prevents abuse/spam)
RATE_LIMIT_WINDOW = 3600  # Time window in seconds (3600 = 1 hour)
RATE_LIMIT_HAGGLE = 5     # Max haggle requests per IP per window
RATE_LIMIT_LOGIN = 10     # Max login attempts per IP per window

# Input validation limits
MAX_MESSAGE_LENGTH = 5000  # Max characters in haggle message
MAX_EMAIL_LENGTH = 254     # Max email address length

# ============================================================================
# END USER CONFIGURATION
# ============================================================================

# Setup logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Allowed RFC1918 networks for admin access
ALLOWED_ADMIN_NETWORKS = ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12', '127.0.0.1/32']

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Blocked user agents (bots, automation tools, etc.)
BLOCKED_USER_AGENTS = [
    'curl', 'wget', 'python-requests', 'python-urllib', 'java', 'go-http-client',
    'rust', 'axios', 'node-fetch', 'postman', 'insomnia', 'httpie', 'scrapy',
    'bot', 'crawler', 'spider', 'scraper', 'archive'
]

# Simple in-memory rate limiting (resets on restart)
rate_limit_store = defaultdict(list)

# Auto-ban list for detected bots/scrapers (resets on restart)
# Structure: {ip_address: (ban_timestamp, reason)}
banned_ips = {}

# Sensitive config keys that should be encrypted
ENCRYPTED_KEYS = [
    'smtp_pass', 'paypal_client_id', 'paypal_secret',
    'square_app_id', 'square_access_token', 'square_location_id'
]

def get_encryption_key():
    """Derive encryption key from SECRET_KEY"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'garagesale_salt_v1',  # Static salt for deterministic key
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(app.config['SECRET_KEY'].encode()))
    return key

def encrypt_value(value):
    """Encrypt a sensitive value"""
    if not value:
        return value
    try:
        f = Fernet(get_encryption_key())
        return f.encrypt(value.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return value

def decrypt_value(encrypted_value):
    """Decrypt a sensitive value"""
    if not encrypted_value:
        return encrypted_value
    try:
        f = Fernet(get_encryption_key())
        return f.decrypt(encrypted_value.encode()).decode()
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return encrypted_value

# Add JSON filter for Jinja2 templates
@app.template_filter('from_json')
def from_json_filter(value):
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return []

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_email_header(value):
    """Remove newlines and control characters from email headers to prevent injection"""
    if not value:
        return ""
    # Remove newlines, carriage returns, null bytes, and other control characters
    return re.sub(r'[\r\n\x00-\x1F\x7F]', '', str(value))

def validate_email_format(email):
    """Simple email validation"""
    if not email or len(email) > MAX_EMAIL_LENGTH:
        return False
    # Basic email regex
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_ip_banned(ip_address):
    """Check if IP is in the ban list"""
    return ip_address in banned_ips

def ban_ip(ip_address, reason):
    """Add IP to ban list"""
    banned_ips[ip_address] = (datetime.now(), reason)
    logger.warning(f"AUTO-BANNED IP {ip_address}: {reason}")

def check_user_agent():
    """Check if user agent looks like an automated tool"""
    user_agent = request.headers.get('User-Agent', '').lower()

    # No user agent = suspicious
    if not user_agent:
        logger.warning(f"Blocked request with no user agent from {request.remote_addr}")
        ban_ip(request.remote_addr, "Nope")
        return False

    # Check against blocked patterns
    for blocked in BLOCKED_USER_AGENTS:
        if blocked in user_agent:
            logger.warning(f"Blocked automated tool '{blocked}' from {request.remote_addr}")
            ban_ip(request.remote_addr, f"Eat shit, bot")
            return False

    return True

def check_referrer():
    """Check if request came from same domain"""
    referrer = request.headers.get('Referer', '')

    # No referrer = suspicious (direct API call)
    if not referrer:
        logger.warning(f"Blocked request with no referrer from {request.remote_addr}")
        ban_ip(request.remote_addr, "Die in a fire, bot")
        return False

    # Parse referrer and check if it's from same host
    try:
        ref_host = urlparse(referrer).netloc
        request_host = request.host

        # Allow both with and without port
        ref_host_base = ref_host.split(':')[0]
        request_host_base = request_host.split(':')[0]

        if ref_host_base != request_host_base:
            logger.warning(f"Blocked cross-origin request from {ref_host} to {request_host}")
            ban_ip(request.remote_addr, f"NO FUCKAROUNDERY")
            return False

        return True
    except Exception:
        ban_ip(request.remote_addr, "gooooo awaaaaaaaayuh")
        return False

def check_rate_limit(ip_address, max_requests=None):
    """Simple IP-based rate limiting"""
    if max_requests is None:
        max_requests = RATE_LIMIT_HAGGLE

    now = datetime.now()

    # Clean old entries
    rate_limit_store[ip_address] = [
        timestamp for timestamp in rate_limit_store[ip_address]
        if now - timestamp < timedelta(seconds=RATE_LIMIT_WINDOW)
    ]

    # Check if over limit
    if len(rate_limit_store[ip_address]) >= max_requests:
        logger.warning(f"Rate limit exceeded for {ip_address} (max: {max_requests})")
        return False

    # Add current request
    rate_limit_store[ip_address].append(now)
    return True

def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

def is_admin_ip(ip_address):
    """Check if IP is in allowed RFC1918 ranges"""
    from ipaddress import ip_address as parse_ip, ip_network
    try:
        ip = parse_ip(ip_address)
        for network in ALLOWED_ADMIN_NETWORKS:
            if ip in ip_network(network):
                return True
    except ValueError:
        return False
    return False

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Optional: Check if request is from private network
        if REQUIRE_PRIVATE_NETWORK and not is_admin_ip(request.remote_addr):
            return "Access denied", 403

        # Always require login
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.after_request
def add_security_headers(response):
    """Add basic security headers to all responses"""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Enable XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Only add CSP for HTML responses (not images/json)
    if response.mimetype == 'text/html':
        # Allow PayPal and Square SDK scripts and iframes
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://www.paypal.com https://sandbox.web.squarecdn.com https://web.squarecdn.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://www.paypal.com https://connect.squareup.com https://connect.squareupsandbox.com; "
            "frame-src https://www.paypal.com https://sandbox.web.squarecdn.com https://web.squarecdn.com;"
        )

    return response

# Public routes
@app.route('/')
def index():
    db = get_db()
    # Show all listings, but sort unsold items first, then sold items
    listings = db.execute(
        'SELECT * FROM listings ORDER BY sold ASC, created_at DESC'
    ).fetchall()

    # Get images for each listing
    listings_with_images = []
    for listing in listings:
        images = db.execute(
            'SELECT * FROM images WHERE listing_id = ? ORDER BY sort_order',
            (listing['id'],)
        ).fetchall()
        listings_with_images.append({
            'listing': dict(listing),
            'images': [dict(img) for img in images]
        })

    return render_template('index.html', listings=listings_with_images)

@app.route('/api/payment-config')
def payment_config():
    """Return public payment configuration (non-sensitive)"""
    db = get_db()
    zelle = db.execute('SELECT value FROM config WHERE key = ?', ('zelle_email',)).fetchone()
    paypal_client_id = db.execute('SELECT value FROM config WHERE key = ?', ('paypal_client_id',)).fetchone()
    square_app_id = db.execute('SELECT value FROM config WHERE key = ?', ('square_app_id',)).fetchone()
    square_location_id = db.execute('SELECT value FROM config WHERE key = ?', ('square_location_id',)).fetchone()

    # Decrypt sensitive values if they exist
    paypal_id = decrypt_value(paypal_client_id['value']) if paypal_client_id else None
    square_app = decrypt_value(square_app_id['value']) if square_app_id else None
    square_loc = decrypt_value(square_location_id['value']) if square_location_id else None

    # Determine if Square is in sandbox mode (check Application ID)
    square_is_sandbox = False
    if square_app:
        # Square sandbox App IDs contain 'sandbox' in them
        square_is_sandbox = 'sandbox' in square_app.lower()

    return jsonify({
        'zelle_email': zelle['value'] if zelle else None,
        'paypal_client_id': paypal_id,
        'square_app_id': square_app,
        'square_location_id': square_loc,
        'square_is_sandbox': square_is_sandbox
    })

@app.route('/api/zelle-qr')
def zelle_qr():
    """Generate Zelle QR code with proper format"""
    db = get_db()
    zelle_email = db.execute('SELECT value FROM config WHERE key = ?', ('zelle_email',)).fetchone()

    if not zelle_email:
        return "Zelle not configured", 404

    # Extract name from email (e.g., "dan" from "dan@atenlabs.com")
    # This matches what appears in most Zelle accounts
    name = zelle_email['value'].split('@')[0].upper()

    # Create Zelle QR data in correct format
    import json
    import base64
    import qrcode
    from io import BytesIO

    zelle_data = {
        "name": name,
        "token": zelle_email['value']
    }

    # Base64 encode the JSON
    json_str = json.dumps(zelle_data)
    encoded_data = base64.b64encode(json_str.encode()).decode()

    # Create the Zelle URL
    zelle_url = f"https://enroll.zellepay.com/qr-codes?data={encoded_data}"

    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(zelle_url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    # Save to BytesIO
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)

    return img_io.getvalue(), 200, {'Content-Type': 'image/png'}

@app.route('/api/paypal-order-complete', methods=['POST'])
def paypal_order_complete():
    """Handle completed PayPal order - mark as sold and send notification"""
    # Check if IP is banned
    if is_ip_banned(request.remote_addr):
        return jsonify({'error': 'Access denied'}), 403

    # Security checks
    if not check_user_agent():
        return jsonify({'error': 'Invalid request'}), 403

    if not check_referrer():
        return jsonify({'error': 'Invalid request'}), 403

    data = request.json
    listing_id = data.get('listing_id')
    transaction_id = data.get('transaction_id', 'N/A')
    customer_name = data.get('customer_name', 'Not provided')
    customer_email = data.get('customer_email', 'Not provided')
    customer_address = data.get('customer_address', 'Not provided')
    amount = data.get('amount', 0)

    if not listing_id:
        return jsonify({'error': 'Missing listing ID'}), 400

    db = get_db()

    # Verify listing exists
    listing = db.execute('SELECT * FROM listings WHERE id = ?', (listing_id,)).fetchone()
    if not listing:
        return jsonify({'error': 'Listing not found'}), 404

    # Mark as sold
    db.execute('UPDATE listings SET sold = 1 WHERE id = ?', (listing_id,))
    db.commit()

    # Send email notification
    try:
        admin_email_row = db.execute('SELECT value FROM config WHERE key = ?', ('admin_email',)).fetchone()
        if admin_email_row:
            send_order_notification_email(
                admin_email_row['value'],
                listing['title'],
                amount,
                customer_name,
                customer_email,
                customer_address,
                transaction_id
            )
    except Exception as e:
        logger.error(f"Failed to send PayPal order notification email: {str(e)}")

    logger.warning(f"Listing {listing_id} marked as sold via PayPal (Transaction: {transaction_id})")

    return jsonify({'success': True})

@app.route('/api/square-payment', methods=['POST'])
def square_payment():
    """Process Square payment - backend only (keeps Access Token secure)"""
    # Check if IP is banned
    if is_ip_banned(request.remote_addr):
        return jsonify({'error': 'Access denied'}), 403

    # Security checks
    if not check_user_agent():
        return jsonify({'error': 'Invalid request'}), 403

    if not check_referrer():
        return jsonify({'error': 'Invalid request'}), 403

    data = request.json
    source_id = data.get('source_id')  # Payment token from Square SDK
    amount_cents = data.get('amount_cents')
    listing_id = data.get('listing_id')
    customer_name = data.get('customer_name', '')
    customer_email = data.get('customer_email', '')
    customer_address = data.get('customer_address', '')

    if not all([source_id, amount_cents, listing_id, customer_name, customer_email, customer_address]):
        return jsonify({'error': 'Missing required fields'}), 400

    db = get_db()

    # Get Square credentials (Access Token stays on backend)
    square_access_token = db.execute('SELECT value FROM config WHERE key = ?', ('square_access_token',)).fetchone()
    square_location_id = db.execute('SELECT value FROM config WHERE key = ?', ('square_location_id',)).fetchone()
    square_app_id = db.execute('SELECT value FROM config WHERE key = ?', ('square_app_id',)).fetchone()

    if not square_access_token or not square_location_id or not square_app_id:
        return jsonify({'error': 'Square not configured'}), 500

    # Decrypt credentials
    access_token = decrypt_value(square_access_token['value'])
    location_id = decrypt_value(square_location_id['value'])
    app_id = decrypt_value(square_app_id['value'])

    # Get listing info
    listing = db.execute('SELECT * FROM listings WHERE id = ?', (listing_id,)).fetchone()
    if not listing:
        return jsonify({'error': 'Listing not found'}), 404

    # Process payment with Square API
    try:
        import requests
        import uuid as uuid_module

        # Log what we received (for debugging)
        logger.warning(f"Square payment attempt: token={source_id[:20]}..., amount={amount_cents}, listing={listing_id}")
        logger.warning(f"Location ID: {location_id}, Access Token: {access_token[:20]}...")

        payment_data = {
            'source_id': source_id,
            'idempotency_key': str(uuid_module.uuid4()),
            'amount_money': {
                'amount': int(amount_cents),
                'currency': 'USD'
            },
            'location_id': location_id,
            'note': f'Garage Sale: {listing["title"]}'
        }

        # Determine if using sandbox based on Application ID (not access token)
        is_sandbox = 'sandbox' in app_id.lower()
        api_url = 'https://connect.squareupsandbox.com/v2/payments' if is_sandbox else 'https://connect.squareup.com/v2/payments'

        headers = {
            'Square-Version': '2024-12-18',
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        logger.warning(f"Posting to Square API: {api_url}")
        logger.warning(f"Payment data: {payment_data}")

        response = requests.post(
            api_url,
            json=payment_data,
            headers=headers,
            timeout=10
        )

        result = response.json()
        logger.warning(f"Square API response ({response.status_code}): {result}")

        if response.status_code == 200:
            # Payment successful - mark listing as sold
            db.execute('UPDATE listings SET sold = 1 WHERE id = ?', (listing_id,))
            db.commit()

            # Send email notification to admin
            try:
                admin_email_row = db.execute('SELECT value FROM config WHERE key = ?', ('admin_email',)).fetchone()
                if admin_email_row:
                    send_order_notification_email(
                        admin_email_row['value'],
                        listing['title'],
                        amount_cents / 100,
                        customer_name,
                        customer_email,
                        customer_address,
                        result['payment']['id']
                    )
            except Exception as e:
                logger.error(f"Failed to send order notification email: {str(e)}")
                # Don't fail the payment if email fails

            return jsonify({
                'success': True,
                'payment_id': result['payment']['id'],
                'status': result['payment']['status']
            })
        else:
            # Get detailed error message
            errors = result.get('errors', [])
            if errors:
                error_msg = errors[0].get('detail', errors[0].get('code', 'Payment failed'))
                error_field = errors[0].get('field', '')
                full_error = f"{error_msg} (field: {error_field})" if error_field else error_msg
            else:
                error_msg = 'Payment failed'
                full_error = error_msg

            logger.error(f"Square payment error: {full_error}, Full response: {result}")
            return jsonify({'error': full_error}), 400

    except Exception as e:
        logger.error(f"Square payment exception: {str(e)}")
        return jsonify({'error': f'Payment processing failed: {str(e)}'}), 500

@app.route('/api/haggle', methods=['POST'])
def haggle():
    # Check if IP is banned
    if is_ip_banned(request.remote_addr):
        return jsonify({'error': 'Access denied'}), 403

    # Security checks
    if not check_user_agent():
        return jsonify({'error': 'Invalid request'}), 403

    if not check_referrer():
        return jsonify({'error': 'Invalid request'}), 403

    if not check_rate_limit(request.remote_addr):
        return jsonify({'error': 'Too many requests. Please try again later.'}), 429

    data = request.json
    listing_id = data.get('listing_id')
    user_email = data.get('email')
    message = data.get('message')

    if not all([listing_id, user_email, message]):
        return jsonify({'error': 'Missing required fields'}), 400

    # Validate email format
    if not validate_email_format(user_email):
        return jsonify({'error': 'Invalid email address'}), 400

    # Validate message length
    if len(message) > MAX_MESSAGE_LENGTH:
        return jsonify({'error': f'Message too long (max {MAX_MESSAGE_LENGTH} characters)'}), 400

    # Sanitize inputs for email headers
    user_email = sanitize_email_header(user_email)
    message = message.strip()

    db = get_db()
    listing = db.execute('SELECT * FROM listings WHERE id = ?', (listing_id,)).fetchone()

    if not listing:
        return jsonify({'error': 'Listing not found'}), 404

    # Get admin email from config
    config = db.execute('SELECT * FROM config WHERE key = ?', ('admin_email',)).fetchone()
    admin_email = config['value'] if config else None

    if not admin_email:
        return jsonify({'error': 'Admin email not configured'}), 500

    # Send email
    try:
        send_haggle_email(admin_email, user_email, listing['title'], message)
        return jsonify({'success': True, 'message': 'Your message has been sent!'})
    except Exception as e:
        logger.error(f"Failed to send haggle email: {str(e)}")
        return jsonify({'error': 'Failed to send message. Please try again later.'}), 500

def send_haggle_email(to_email, from_email, item_title, message):
    """Send haggle email using SMTP settings from config"""
    db = get_db()

    # Get SMTP settings from config
    smtp_host = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_host',)).fetchone()
    smtp_port = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_port',)).fetchone()
    smtp_user = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_user',)).fetchone()
    smtp_pass = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_pass',)).fetchone()
    smtp_from = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_from',)).fetchone()
    smtp_use_tls = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_use_tls',)).fetchone()

    if not smtp_host or not smtp_port:
        raise Exception("SMTP host and port must be configured")

    # Use smtp_from if configured, otherwise use smtp_user, otherwise use admin email
    from_address = smtp_from['value'] if smtp_from else (smtp_user['value'] if smtp_user else to_email)

    msg = MIMEMultipart()
    msg['From'] = sanitize_email_header(from_address)
    msg['To'] = sanitize_email_header(to_email)
    msg['Reply-To'] = sanitize_email_header(from_email)
    msg['Subject'] = sanitize_email_header(f'Haggle Request: {item_title}')

    body = f"""
You have received a haggle request for: {item_title}

From: {from_email}

Message:
{message}

Reply to this email to continue the conversation.
"""

    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP(smtp_host['value'], int(smtp_port['value']))

    # Only use STARTTLS if configured (default to True for backwards compatibility)
    use_tls = smtp_use_tls['value'].lower() in ['true', '1', 'yes'] if smtp_use_tls else True
    if use_tls:
        server.starttls()

    # Only authenticate if username and password are provided
    if smtp_user and smtp_pass:
        # Decrypt password before using
        password = decrypt_value(smtp_pass['value'])
        server.login(smtp_user['value'], password)

    server.send_message(msg)
    server.quit()

def send_order_notification_email(to_email, item_title, amount, customer_name, customer_email, customer_address, payment_id):
    """Send order notification email to admin when payment is successful"""
    db = get_db()

    smtp_host = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_host',)).fetchone()
    smtp_port = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_port',)).fetchone()
    smtp_user = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_user',)).fetchone()
    smtp_pass = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_pass',)).fetchone()
    smtp_from = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_from',)).fetchone()
    smtp_use_tls = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_use_tls',)).fetchone()

    if not smtp_host or not smtp_port:
        raise Exception("SMTP host and port must be configured")

    from_address = smtp_from['value'] if smtp_from else (smtp_user['value'] if smtp_user else to_email)

    msg = MIMEMultipart()
    msg['From'] = sanitize_email_header(from_address)
    msg['To'] = sanitize_email_header(to_email)
    msg['Subject'] = sanitize_email_header(f'New Order: {item_title}')

    body = f"""
You have received a new order!

Item: {item_title}
Amount Paid: ${amount:.2f}
Payment ID: {payment_id}

CUSTOMER INFORMATION:
Name: {customer_name}
Email: {customer_email}
Shipping Address:
{customer_address}

Please contact the customer to arrange shipping/pickup.
"""

    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP(smtp_host['value'], int(smtp_port['value']))

    use_tls = smtp_use_tls['value'].lower() in ['true', '1', 'yes'] if smtp_use_tls else True
    if use_tls:
        server.starttls()

    if smtp_user and smtp_pass:
        password = decrypt_value(smtp_pass['value'])
        server.login(smtp_user['value'], password)

    server.send_message(msg)
    server.quit()

def send_test_email(to_email):
    """Send a test email to verify SMTP configuration"""
    db = get_db()

    smtp_host = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_host',)).fetchone()
    smtp_port = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_port',)).fetchone()
    smtp_user = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_user',)).fetchone()
    smtp_pass = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_pass',)).fetchone()
    smtp_from = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_from',)).fetchone()
    smtp_use_tls = db.execute('SELECT value FROM config WHERE key = ?', ('smtp_use_tls',)).fetchone()

    if not smtp_host or not smtp_port:
        raise Exception("SMTP host and port must be configured")

    from_address = smtp_from['value'] if smtp_from else (smtp_user['value'] if smtp_user else to_email)

    msg = MIMEMultipart()
    msg['From'] = from_address
    msg['To'] = to_email
    msg['Subject'] = 'Test Email from Garage Sale'

    body = """
This is a test email from your Garage Sale application.

If you're receiving this, your SMTP settings are configured correctly!

SMTP Configuration:
- Host: {}
- Port: {}
- Authentication: {}
- TLS: {}
""".format(
        smtp_host['value'],
        smtp_port['value'],
        'Enabled' if (smtp_user and smtp_pass) else 'Disabled (LAN mode)',
        'Enabled' if (smtp_use_tls and smtp_use_tls['value'].lower() in ['true', '1', 'yes']) else 'Disabled'
    )

    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP(smtp_host['value'], int(smtp_port['value']))

    use_tls = smtp_use_tls['value'].lower() in ['true', '1', 'yes'] if smtp_use_tls else True
    if use_tls:
        server.starttls()

    if smtp_user and smtp_pass:
        # Decrypt password before using
        password = decrypt_value(smtp_pass['value'])
        server.login(smtp_user['value'], password)

    server.send_message(msg)
    server.quit()

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    # Optional: Check if request is from private network
    if REQUIRE_PRIVATE_NETWORK and not is_admin_ip(request.remote_addr):
        return "Access denied: Admin section only accessible from internal network", 403

    if request.method == 'POST':
        # Rate limiting for login attempts
        if not check_rate_limit(request.remote_addr, max_requests=RATE_LIMIT_LOGIN):
            return render_template('admin_login.html', error='Too many login attempts. Please try again later.')

        password = request.form.get('password')

        db = get_db()
        admin_pass = db.execute('SELECT value FROM config WHERE key = ?', ('admin_password',)).fetchone()

        if admin_pass and check_password_hash(admin_pass['value'], password):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error='Invalid password')

    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    listings = db.execute('SELECT * FROM listings ORDER BY created_at DESC').fetchall()

    # Get images for each listing
    listings_with_images = []
    for listing in listings:
        images = db.execute(
            'SELECT * FROM images WHERE listing_id = ? ORDER BY sort_order',
            (listing['id'],)
        ).fetchall()
        listings_with_images.append({
            'listing': dict(listing),
            'images': [dict(img) for img in images]
        })

    return render_template('admin_dashboard.html', listings=listings_with_images)

@app.route('/admin/listing/new', methods=['GET', 'POST'])
@admin_required
def admin_new_listing():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        price = request.form.get('price')
        payment_methods = request.form.getlist('payment_methods')

        if not all([title, description, price]):
            return "Missing required fields", 400

        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            'INSERT INTO listings (title, description, price, payment_methods, sold) VALUES (?, ?, ?, ?, 0)',
            (title, description, float(price), json.dumps(payment_methods))
        )
        listing_id = cursor.lastrowid

        # Handle image uploads
        files = request.files.getlist('images')
        for idx, file in enumerate(files):
            if file and allowed_file(file.filename):
                filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                cursor.execute(
                    'INSERT INTO images (listing_id, filename, sort_order) VALUES (?, ?, ?)',
                    (listing_id, filename, idx)
                )

        db.commit()
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_listing_form.html', listing=None)

@app.route('/admin/listing/<int:listing_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_listing(listing_id):
    db = get_db()

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        price = request.form.get('price')
        payment_methods = request.form.getlist('payment_methods')

        db.execute(
            'UPDATE listings SET title = ?, description = ?, price = ?, payment_methods = ? WHERE id = ?',
            (title, description, float(price), json.dumps(payment_methods), listing_id)
        )
        db.commit()

        return redirect(url_for('admin_dashboard'))

    listing = db.execute('SELECT * FROM listings WHERE id = ?', (listing_id,)).fetchone()
    images = db.execute('SELECT * FROM images WHERE listing_id = ? ORDER BY sort_order', (listing_id,)).fetchall()

    return render_template('admin_listing_form.html', listing=dict(listing), images=[dict(img) for img in images])

@app.route('/admin/listing/<int:listing_id>/mark-sold', methods=['POST'])
@admin_required
def admin_mark_sold(listing_id):
    db = get_db()
    db.execute('UPDATE listings SET sold = 1 WHERE id = ?', (listing_id,))
    db.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/listing/<int:listing_id>/unmark-sold', methods=['POST'])
@admin_required
def admin_unmark_sold(listing_id):
    db = get_db()
    db.execute('UPDATE listings SET sold = 0 WHERE id = ?', (listing_id,))
    db.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/listing/<int:listing_id>/delete', methods=['POST'])
@admin_required
def admin_delete_listing(listing_id):
    db = get_db()

    # Delete images from filesystem
    images = db.execute('SELECT filename FROM images WHERE listing_id = ?', (listing_id,)).fetchall()
    for img in images:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], img['filename']))
        except OSError:
            pass

    # Delete from database
    db.execute('DELETE FROM images WHERE listing_id = ?', (listing_id,))
    db.execute('DELETE FROM listings WHERE id = ?', (listing_id,))
    db.commit()

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    db = get_db()

    if request.method == 'POST':
        # Update config values
        for key in ['admin_email', 'smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'smtp_from', 'smtp_use_tls',
                    'paypal_client_id', 'square_app_id', 'square_location_id', 'square_access_token', 'zelle_email']:
            value = request.form.get(key)
            if value:
                # Encrypt sensitive keys before storing
                stored_value = encrypt_value(value) if key in ENCRYPTED_KEYS else value
                db.execute(
                    'INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)',
                    (key, stored_value)
                )
            elif key == 'smtp_use_tls':
                # Handle checkbox - if not checked, value will be empty
                db.execute(
                    'INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)',
                    (key, 'false')
                )

        # Handle password change
        new_password = request.form.get('new_password')
        if new_password:
            hashed = generate_password_hash(new_password)
            db.execute(
                'INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)',
                ('admin_password', hashed)
            )

        db.commit()
        return redirect(url_for('admin_settings'))

    # Get current config
    config = {}
    rows = db.execute('SELECT key, value FROM config').fetchall()
    for row in rows:
        if row['key'] != 'admin_password':  # Don't send password to template
            # Decrypt sensitive values for display
            value = decrypt_value(row['value']) if row['key'] in ENCRYPTED_KEYS else row['value']
            config[row['key']] = value

    return render_template('admin_settings.html', config=config)

@app.route('/admin/test-square', methods=['POST'])
@admin_required
def admin_test_square():
    """Test Square connection and fetch available locations"""
    db = get_db()
    square_access_token = db.execute('SELECT value FROM config WHERE key = ?', ('square_access_token',)).fetchone()
    square_app_id = db.execute('SELECT value FROM config WHERE key = ?', ('square_app_id',)).fetchone()

    if not square_access_token:
        return jsonify({'error': 'Square Access Token not configured'}), 400

    if not square_app_id:
        return jsonify({'error': 'Square Application ID not configured'}), 400

    try:
        import requests

        access_token = decrypt_value(square_access_token['value'])
        app_id = decrypt_value(square_app_id['value'])

        # Determine environment from Application ID (reliable), not Access Token
        is_sandbox = 'sandbox' in app_id.lower()
        api_url = 'https://connect.squareupsandbox.com/v2/locations' if is_sandbox else 'https://connect.squareup.com/v2/locations'

        headers = {
            'Square-Version': '2024-12-18',
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        response = requests.get(api_url, headers=headers, timeout=10)
        result = response.json()

        if response.status_code == 200:
            locations = result.get('locations', [])
            location_info = [
                {
                    'id': loc['id'],
                    'name': loc.get('name', 'Unnamed'),
                    'status': loc.get('status', 'UNKNOWN')
                }
                for loc in locations
            ]
            return jsonify({
                'success': True,
                'environment': 'Sandbox' if is_sandbox else 'Production',
                'locations': location_info,
                'message': f'Found {len(locations)} location(s). Use one of these Location IDs in your settings.'
            })
        else:
            error_msg = result.get('errors', [{}])[0].get('detail', 'Failed to fetch locations')
            return jsonify({'error': error_msg}), 400

    except Exception as e:
        return jsonify({'error': f'Failed to test Square: {str(e)}'}), 500

@app.route('/admin/test-email', methods=['POST'])
@admin_required
def admin_test_email():
    db = get_db()
    admin_email = db.execute('SELECT value FROM config WHERE key = ?', ('admin_email',)).fetchone()

    if not admin_email:
        return jsonify({'error': 'Admin email not configured'}), 400

    try:
        send_test_email(admin_email['value'])
        return jsonify({'success': True, 'message': f'Test email sent to {admin_email["value"]}!'})
    except Exception as e:
        return jsonify({'error': f'Failed to send test email: {str(e)}'}), 500

if __name__ == '__main__':
    # Create upload folder if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Initialize database if it doesn't exist
    if not os.path.exists(app.config['DATABASE']):
        init_db()

    # NEVER use debug=True in production!
    # Use gunicorn or uwsgi for production deployment
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
