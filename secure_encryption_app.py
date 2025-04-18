import streamlit as st  # Web app framework for Python
import hashlib  # For password hashing
import time  # For lockout timing and 2FA expiration
import re  # For password strength regex validation
from base64 import urlsafe_b64encode  # For encoding encryption keys
from hashlib import pbkdf2_hmac  # For key derivation
from datetime import datetime  # For audit log timestamps
import secrets  # For generating secure 2FA codes
from pymongo import MongoClient  # For MongoDB connectivity
import os  # For environment variables

try:
    from cryptography.fernet import Fernet  # For symmetric encryption
except ImportError:
    # Display error and stop if cryptography package is missing
    st.error("Please install the cryptography package. Run: pip install cryptography")
    st.stop()

# Constants
DB_NAME = "encryption_system"  # MongoDB database name
SALT = b"secure_salt_value"  # Salt for password hashing and key derivation
LOCKOUT_DURATION = 60  # Lockout duration in seconds
MASTER_PASSWORD = "admin123"  # Master password for backups and audit log
MIN_PASSWORD_STRENGTH = 3  # Minimum password strength score
TFA_EXPIRY = 30  # 2FA code expiration time in seconds

# MongoDB Connection
try:
    # Use environment variable for MongoDB URI or default to local
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    users_collection = db["users"]  # Collection for user credentials
    data_collection = db["data"]  # Collection for encrypted data
    audit_collection = db["audit_logs"]  # Collection for audit logs
except Exception as e:
    st.error(f"Failed to connect to MongoDB: {str(e)}")
    st.stop()

# Session State Initialization
# Initialize session state for authentication and security tracking
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None  # Tracks logged-in user
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0  # Tracks failed attempts
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0  # Tracks lockout start time
if "tfa_code" not in st.session_state:
    st.session_state.tfa_code = None  # Stores 2FA code
if "tfa_timestamp" not in st.session_state:
    st.session_state.tfa_timestamp = 0  # Tracks 2FA code generation time

# Helper Functions
def validate_password_strength(password):
    """Validate password strength based on length and character types."""
    score = 0
    if len(password) >= 8:  # At least 8 characters
        score += 1
    if re.search(r"[A-Z]", password):  # Contains uppercase
        score += 1
    if re.search(r"[a-z]", password):  # Contains lowercase
        score += 1
    if re.search(r"[0-9]", password):  # Contains numbers
        score += 1
    if re.search(r"[^A-Za-z0-9]", password):  # Contains special characters
        score += 1
    return score

def log_audit_event(event_type, username, details=""):
    """Log an event to the MongoDB audit_logs collection."""
    audit_entry = {
        "timestamp": datetime.now().isoformat(),  # Current timestamp
        "event_type": event_type,  # Event type (e.g., LOGIN_SUCCESS)
        "username": username,  # Associated user
        "details": details  # Additional details
    }
    audit_collection.insert_one(audit_entry)  # Insert into MongoDB

# Data Management
def load_user_data(username):
    """Load user data from MongoDB, return empty dict if user doesn't exist."""
    user = users_collection.find_one({"username": username})
    if user:
        return {
            "password": user["password"],
            "data": user.get("data", []),
            "categories": user.get("categories", {})
        }
    return {"password": "", "data": [], "categories": {}}

def save_user_data(username, user_data):
    """Save or update user data in MongoDB."""
    users_collection.update_one(
        {"username": username},
        {"$set": {
            "password": user_data["password"],
            "data": user_data["data"],
            "categories": user_data["categories"]
        }},
        upsert=True
    )

def load_audit_log(username):
    """Load audit logs for a specific user from MongoDB."""
    return list(audit_collection.find({"username": username}))

# Encryption / Decryption
def generate_key(passkey):
    """Generate a Fernet-compatible key from a passkey using PBKDF2."""
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    """Hash a password using PBKDF2 for secure storage."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, passkey):
    """Encrypt text using Fernet with a passkey-derived key."""
    key = generate_key(passkey)
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(text.encode())
    return encrypted_data.decode('utf-8')

def decrypt_text(encrypted_text, passkey):
    """Decrypt text using Fernet with a passkey-derived key."""
    key = generate_key(passkey)
    cipher = Fernet(key)
    decrypted_data = cipher.decrypt(encrypted_text.encode('utf-8'))
    return decrypted_data.decode('utf-8')

# Backup Functions
def export_backup(username, master_password):
    """Export user's encrypted data as a backup if master password is correct."""
    if master_password != MASTER_PASSWORD:
        return None
    user_data = load_user_data(username)
    backup_data = json.dumps(user_data)
    backup_key = generate_key(master_password)
    cipher = Fernet(backup_key)
    encrypted_backup = cipher.encrypt(backup_data.encode())
    return encrypted_backup

def import_backup(encrypted_backup, master_password, username):
    """Import and decrypt a backup if master password is correct."""
    if master_password != MASTER_PASSWORD:
        return False
    try:
        backup_key = generate_key(master_password)
        cipher = Fernet(backup_key)
        decrypted_backup = cipher.decrypt(encrypted_backup).decode()
        backup_data = json.loads(decrypted_backup)
        save_user_data(username, backup_data)
        return True
    except:
        return False

# UI Navigation
st.title("🛡️ Advanced Secure Data Encryption System (MongoDB)")  # App title
# Navigation menu with added logout option
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Search Data", "Backup Management", "Audit Log", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home Page
if choice == "Home":
    st.subheader("✨ Welcome to the Advanced 🔐 Secure Data Encryption System!")
    st.markdown("""
    Advanced features include:
    - Strong password validation
    - Data categorization
    - Search functionality
    - Encrypted backups
    - Audit logging
    - Two-factor authentication
    - MongoDB storage
    """)

# Register Page
elif choice == "Register":
    st.subheader("✍ Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")
    
    if password:
        strength = validate_password_strength(password)
        st.progress(strength / 5)
        st.write(f"Password Strength: {strength}/5")
        
    if st.button("Register"):
        if username and password:
            if strength < MIN_PASSWORD_STRENGTH:
                st.error(f"⚠️ Password too weak! Minimum strength: {MIN_PASSWORD_STRENGTH}/5")
            elif users_collection.find_one({"username": username}):
                st.error("⚠️ Username already exists.")
            else:
                user_data = {
                    "password": hash_password(password),
                    "data": [],
                    "categories": {}
                }
                save_user_data(username, user_data)
                log_audit_event("REGISTER", username)
                st.success("✅ Registered successfully!")
        else:
            st.error("⚠️ All fields are required!")

# Login Page
elif choice == "Login":
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    tfa_code = st.text_input("2FA Code (if enabled)", type="password")

    if st.button("Generate 2FA Code"):
        st.session_state.tfa_code = secrets.token_hex(4)
        st.session_state.tfa_timestamp = time.time()
        st.success(f"2FA Code: {st.session_state.tfa_code} (Valid for {TFA_EXPIRY} seconds)")

    if st.button("Login"):
        user = users_collection.find_one({"username": username})
        if user and user["password"] == hash_password(password):
            # Check 2FA if enabled
            if st.session_state.tfa_code:
                if time.time() > st.session_state.tfa_timestamp + TFA_EXPIRY:
                    st.error("❌ 2FA code expired!")
                    log_audit_event("LOGIN_FAILED", username, "Expired 2FA")
                    st.session_state.tfa_code = None
                    st.session_state.tfa_timestamp = 0
                elif tfa_code != st.session_state.tfa_code:
                    st.error("❌ Invalid 2FA code!")
                    log_audit_event("LOGIN_FAILED", username, "Invalid 2FA")
                else:
                    # Successful login with 2FA
                    st.session_state.authenticated_user = username
                    st.session_state.failed_attempts = 0
                    st.session_state.tfa_code = None
                    st.session_state.tfa_timestamp = 0
                    log_audit_event("LOGIN_SUCCESS", username)
                    st.success("✅ Logged in successfully!")
            else:
                # Successful login without 2FA
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                log_audit_event("LOGIN_SUCCESS", username)
                st.success("✅ Logged in successfully!")
        else:
            st.session_state.failed_attempts += 1
            log_audit_event("LOGIN_FAILED", username, "Invalid credentials")
            st.error(f"❌ Incorrect username or password! Attempts left: {3 - st.session_state.failed_attempts}")

# Store Data Page
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login to store data.")
    else:
        st.subheader("📂 Store Data Securely")
        category = st.selectbox("Category", ["Personal", "Work", "Financial", "Other"])
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Encrypt & Save"):
            if user_data and passkey:
                encrypted = encrypt_text(user_data, passkey)
                data_entry = {
                    "encrypted_data": encrypted,
                    "timestamp": datetime.now().isoformat(),
                    "category": category
                }
                user_data = load_user_data(st.session_state.authenticated_user)
                if category not in user_data["categories"]:
                    user_data["categories"][category] = []
                user_data["categories"][category].append(data_entry)
                user_data["data"].append(encrypted)
                save_user_data(st.session_state.authenticated_user, user_data)
                log_audit_event("DATA_STORED", st.session_state.authenticated_user, f"Category: {category}")
                st.success("✅ Data stored securely!")
            else:
                st.error("⚠️ All fields are required!")

# Retrieve Data Page
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login to retrieve data.")
    elif st.session_state.failed_attempts >= 3:
        if time.time() < st.session_state.lockout_time + LOCKOUT_DURATION:
            remaining = int((st.session_state.lockout_time + LOCKOUT_DURATION) - time.time())
            st.error(f"🔒 Locked out due to multiple failed attempts. Try again in {remaining} seconds.")
            st.stop()
        else:
            st.session_state.failed_attempts = 0

    st.subheader("🔍 Retrieve Your Data")
    user_data = load_user_data(st.session_state.authenticated_user)
    category = st.selectbox("Filter by Category", ["All"] + list(user_data["categories"].keys()))
    passkey = st.text_input("Enter Passkey to Decrypt:", type="password")

    if st.button("Decrypt All"):
        if passkey:
            try:
                data_list = user_data["categories"].get(category, []) if category != "All" else user_data["data"]
                for idx, item in enumerate(data_list):
                    encrypted = item["encrypted_data"] if category != "All" else item
                    decrypted = decrypt_text(encrypted, passkey)
                    category_info = f"Category: {item['category']}, " if category != "All" else ""
                    st.success(f"Data {idx+1}: {category_info}Timestamp: {item['timestamp'] if category != 'All' else 'N/A'}\n{decrypted}")
                st.session_state.failed_attempts = 0
                log_audit_event("DATA_RETRIEVED", st.session_state.authenticated_user, f"Category: {category}")
            except Exception as e:
                st.session_state.failed_attempts += 1
                st.session_state.lockout_time = time.time()
                log_audit_event("DECRYPTION_FAILED", st.session_state.authenticated_user, str(e))
                st.error(f"❌ Incorrect passkey! Attempts left: {3 - st.session_state.failed_attempts}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Locked out.")
        else:
            st.error("⚠️ Passkey is required!")

# Search Data Page
elif choice == "Search Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login to search data.")
    else:
        st.subheader("🔎 Search Encrypted Data")
        search_term = st.text_input("Search Term")
        passkey = st.text_input("Enter Passkey to Decrypt:", type="password")
        
        if st.button("Search"):
            if search_term and passkey:
                try:
                    user_data = load_user_data(st.session_state.authenticated_user)
                    found = False
                    for category, items in user_data["categories"].items():
                        for idx, item in enumerate(items):
                            decrypted = decrypt_text(item["encrypted_data"], passkey)
                            if search_term.lower() in decrypted.lower():
                                found = True
                                st.success(f"Match in {category} (Entry {idx+1}): {decrypted}")
                    if not found:
                        st.info("No matches found.")
                    log_audit_event("DATA_SEARCH", st.session_state.authenticated_user, f"Term: {search_term}")
                except Exception:
                    st.error("❌ Incorrect passkey!")
                    log_audit_event("SEARCH_FAILED", st.session_state.authenticated_user, "Invalid passkey")
            else:
                st.error("⚠️ Both fields are required!")

# Backup Management Page
elif choice == "Backup Management":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login to manage backups.")
    else:
        st.subheader("💾 Backup Management")
        master_password = st.text_input("Master Password", type="password")
        
        st.write("### Export Backup")
        if st.button("Export Encrypted Backup"):
            if master_password:
                backup = export_backup(st.session_state.authenticated_user, master_password)
                if backup:
                    st.download_button(
                        label="Download Backup",
                        data=backup,
                        file_name=f"backup_{st.session_state.authenticated_user}.enc",
                        mime="application/octet-stream"
                    )
                    log_audit_event("BACKUP_EXPORT", st.session_state.authenticated_user)
                else:
                    st.error("❌ Invalid master password!")
                    log_audit_event("BACKUP_EXPORT_FAILED", st.session_state.authenticated_user)
            else:
                st.error("⚠️ Master password required!")

        st.write("### Import Backup")
        uploaded_file = st.file_uploader("Upload Backup File", type=["enc"])
        if uploaded_file and st.button("Import Backup"):
            if master_password:
                if import_backup(uploaded_file.read(), master_password, st.session_state.authenticated_user):
                    st.success("✅ Backup imported successfully!")
                    log_audit_event("BACKUP_IMPORT", st.session_state.authenticated_user)
                else:
                    st.error("❌ Failed to import backup! Invalid password or corrupted file.")
                    log_audit_event("BACKUP_IMPORT_FAILED", st.session_state.authenticated_user)
            else:
                st.error("⚠️ Master password required!")

# Audit Log Page
elif choice == "Audit Log":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login to view audit log.")
    else:
        st.subheader("📜 Audit Log")
        master_password = st.text_input("Master Password for Audit Log", type="password")
        
        if st.button("View Audit Log"):
            if master_password == MASTER_PASSWORD:
                audit_log = load_audit_log(st.session_state.authenticated_user)
                for entry in audit_log:
                    st.write(f"[{entry['timestamp']}] {entry['event_type']}: {entry['details']}")
                log_audit_event("AUDIT_VIEW", st.session_state.authenticated_user)
            else:
                st.error("❌ Invalid master password!")
                log_audit_event("AUDIT_VIEW_FAILED", st.session_state.authenticated_user)

# Logout Page
elif choice == "Logout":
    st.subheader("🚪 Logout")
    if st.button("Confirm Logout"):
        st.session_state.authenticated_user = None
        st.session_state.failed_attempts = 0
        st.session_state.tfa_code = None
        st.session_state.tfa_timestamp = 0
        log_audit_event("LOGOUT", st.session_state.authenticated_user or "unknown")
        st.success("✅ Logged out successfully!")
        st.experimental_rerun()  # Refresh to clear UI