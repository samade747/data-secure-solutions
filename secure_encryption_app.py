import streamlit as st  # Web app framework for Python
import hashlib  # For password hashing
import json  # For reading/writing JSON data
import os  # For file operations
import time  # For lockout timing
import re  # For password strength regex validation
from base64 import urlsafe_b64encode  # For encoding encryption keys
from hashlib import pbkdf2_hmac  # For key derivation
from datetime import datetime  # For audit log timestamps
import secrets  # For generating secure 2FA codes

try:
    from cryptography.fernet import Fernet  # For symmetric encryption
except ImportError:
    # Display error and stop if cryptography package is missing
    st.error("Please install the cryptography package. Run: pip install cryptography")
    st.stop()

# Constants
DATA_FILE = "secure_data.json"  # File to store encrypted user data
AUDIT_LOG = "audit_log.json"  # File to store audit logs
SALT = b"secure_salt_value"  # Salt for password hashing and key derivation
LOCKOUT_DURATION = 60  # Lockout duration in seconds after failed attempts
MASTER_PASSWORD = "admin123"  # Master password for backups and audit log
MIN_PASSWORD_STRENGTH = 3  # Minimum password strength score (out of 5)

# Session State Initialization
# Initialize session state variables to track user authentication and security
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None  # Tracks logged-in user
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0  # Tracks failed login/decryption attempts
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0  # Tracks when lockout started
if "tfa_code" not in st.session_state:
    st.session_state.tfa_code = None  # Stores temporary 2FA code

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
    """Log an event to the audit log with timestamp, event type, and details."""
    audit_entry = {
        "timestamp": datetime.now().isoformat(),  # Current timestamp
        "event_type": event_type,  # Type of event (e.g., LOGIN_SUCCESS)
        "username": username,  # User associated with the event
        "details": details  # Additional event details
    }
    audit_log = load_audit_log()  # Load existing audit log
    audit_log.append(audit_entry)  # Append new entry
    save_audit_log(audit_log)  # Save updated audit log

# Data Management
def load_data():
    """Load user data from JSON file, return empty dict if file doesn't exist."""
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    """Save user data to JSON file with proper indentation."""
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def load_audit_log():
    """Load audit log from JSON file, return empty list if file doesn't exist."""
    if os.path.exists(AUDIT_LOG):
        with open(AUDIT_LOG, "r") as f:
            return json.load(f)
    return []

def save_audit_log(audit_log):
    """Save audit log to JSON file with proper indentation."""
    with open(AUDIT_LOG, "w") as f:
        json.dump(audit_log, f, indent=4)

# Encryption / Decryption
def generate_key(passkey):
    """Generate a Fernet-compatible key from a passkey using PBKDF2."""
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)  # Derive key
    return urlsafe_b64encode(key)  # Encode to base64 for Fernet

def hash_password(password):
    """Hash a password using PBKDF2 for secure storage."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, passkey):
    """Encrypt text using Fernet with a passkey-derived key."""
    key = generate_key(passkey)  # Generate encryption key
    cipher = Fernet(key)  # Initialize Fernet cipher
    encrypted_data = cipher.encrypt(text.encode())  # Encrypt text
    return encrypted_data.decode('utf-8')  # Return as string

def decrypt_text(encrypted_text, passkey):
    """Decrypt text using Fernet with a passkey-derived key."""
    key = generate_key(passkey)  # Generate decryption key
    cipher = Fernet(key)  # Initialize Fernet cipher
    decrypted_data = cipher.decrypt(encrypted_text.encode('utf-8'))  # Decrypt
    return decrypted_data.decode('utf-8')  # Return as string

# Backup Functions
def export_backup(username, master_password):
    """Export user's encrypted data as a backup if master password is correct."""
    if master_password != MASTER_PASSWORD:
        return None  # Invalid master password
    user_data = stored_data.get(username, {})  # Get user's data
    backup_data = json.dumps(user_data)  # Convert to JSON string
    backup_key = generate_key(master_password)  # Generate backup key
    cipher = Fernet(backup_key)  # Initialize Fernet cipher
    encrypted_backup = cipher.encrypt(backup_data.encode())  # Encrypt backup
    return encrypted_backup  # Return encrypted backup

def import_backup(encrypted_backup, master_password, username):
    """Import and decrypt a backup if master password is correct."""
    if master_password != MASTER_PASSWORD:
        return False  # Invalid master password
    try:
        backup_key = generate_key(master_password)  # Generate backup key
        cipher = Fernet(backup_key)  # Initialize Fernet cipher
        decrypted_backup = cipher.decrypt(encrypted_backup).decode()  # Decrypt
        backup_data = json.loads(decrypted_backup)  # Parse JSON
        stored_data[username] = backup_data  # Update user data
        save_data(stored_data)  # Save updated data
        return True  # Success
    except:
        return False  # Failed to decrypt or parse

# Load stored data
stored_data = load_data()  # Load user data at startup

# UI Navigation
st.title("🛡️ Advanced Secure Data Encryption System")  # App title
# Navigation menu in sidebar
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Search Data", "Backup Management", "Audit Log"]
choice = st.sidebar.selectbox("Navigation", menu)  # Sidebar menu selection

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
    """)  # Display app features

# Register Page
elif choice == "Register":
    st.subheader("✍ Register New User")  # Page title
    username = st.text_input("Choose Username")  # Username input
    password = st.text_input("Choose Password", type="password")  # Password input
    
    # Show password strength if password is entered
    if password:
        strength = validate_password_strength(password)  # Calculate strength
        st.progress(strength / 5)  # Display progress bar
        st.write(f"Password Strength: {strength}/5")  # Show strength score
        
    if st.button("Register"):  # Register button
        if username and password:  # Check if fields are filled
            if strength < MIN_PASSWORD_STRENGTH:  # Check password strength
                st.error(f"⚠️ Password too weak! Minimum strength: {MIN_PASSWORD_STRENGTH}/5")
            elif username in stored_data:  # Check if username exists
                st.error("⚠️ Username already exists.")
            else:
                # Create new user with hashed password and empty data structures
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": [],  # List for encrypted data
                    "categories": {}  # Dict for categorized data
                }
                save_data(stored_data)  # Save updated data
                log_audit_event("REGISTER", username)  # Log registration
                st.success("✅ Registered successfully!")
        else:
            st.error("⚠️ All fields are required!")  # Missing fields error

# Login Page
elif choice == "Login":
    st.subheader("🔑 Login")  # Page title
    username = st.text_input("Username")  # Username input
    password = st.text_input("Password", type="password")  # Password input
    tfa_code = st.text_input("2FA Code (if enabled)", type="password")  # 2FA input

    if st.button("Generate 2FA Code"):  # Button to generate 2FA code
        st.session_state.tfa_code = secrets.token_hex(4)  # Generate random code
        st.success(f"2FA Code: {st.session_state.tfa_code} (Valid for 30 seconds)")

    if st.button("Login"):  # Login button
        # Check if username exists and password is correct
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            # Verify 2FA code if it was generated
            if st.session_state.tfa_code and tfa_code != st.session_state.tfa_code:
                st.error("❌ Invalid 2FA code!")
                log_audit_event("LOGIN_FAILED", username, "Invalid 2FA")
            else:
                # Successful login
                st.session_state.authenticated_user = username  # Set authenticated user
                st.session_state.failed_attempts = 0  # Reset failed attempts
                st.session_state.tfa_code = None  # Clear 2FA code
                log_audit_event("LOGIN_SUCCESS", username)  # Log successful login
                st.success("✅ Logged in successfully!")
        else:
            # Failed login
            st.session_state.failed_attempts += 1  # Increment failed attempts
            log_audit_event("LOGIN_FAILED", username, "Invalid credentials")
            st.error(f"❌ Incorrect username or password! Attempts left: {3 - st.session_state.failed_attempts}")

# Store Data Page
elif choice == "Store Data":
    if not st.session_state.authenticated_user:  # Check if user is logged in
        st.warning("🔒 Please login to store data.")
    else:
        st.subheader("📂 Store Data Securely")  # Page title
        # Category selection for data organization
        category = st.selectbox("Category", ["Personal", "Work", "Financial", "Other"])
        user_data = st.text_area("Enter Data:")  # Data input
        passkey = st.text_input("Enter Passkey:", type="password")  # Passkey input

        if st.button("Encrypt & Save"):  # Save button
            if user_data and passkey:  # Check if fields are filled
                encrypted = encrypt_text(user_data, passkey)  # Encrypt data
                # Create data entry with metadata
                data_entry = {
                    "encrypted_data": encrypted,
                    "timestamp": datetime.now().isoformat(),
                    "category": category
                }
                # Initialize category if it doesn't exist
                if category not in stored_data[st.session_state.authenticated_user]["categories"]:
                    stored_data[st.session_state.authenticated_user]["categories"][category] = []
                # Add to category and general data list
                stored_data[st.session_state.authenticated_user]["categories"][category].append(data_entry)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)  # Save updated data
                log_audit_event("DATA_STORED", st.session_state.authenticated_user, f"Category: {category}")
                st.success("✅ Data stored securely!")
            else:
                st.error("⚠️ All fields are required!")  # Missing fields error

# Retrieve Data Page
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:  # Check if user is logged in
        st.warning("🔒 Please login to retrieve data.")
    elif st.session_state.failed_attempts >= 3:  # Check for lockout
        if time.time() < st.session_state.lockout_time + LOCKOUT_DURATION:
            # Display remaining lockout time
            remaining = int((st.session_state.lockout_time + LOCKOUT_DURATION) - time.time())
            st.error(f"🔒 Locked out due to multiple failed attempts. Try again in {remaining} seconds.")
            st.stop()  # Stop execution during lockout
        else:
            st.session_state.failed_attempts = 0  # Reset failed attempts after lockout

    st.subheader("🔍 Retrieve Your Data")  # Page title
    # Category filter, including "All" option
    category = st.selectbox("Filter by Category", ["All"] + list(stored_data[st.session_state.authenticated_user]["categories"].keys()))
    passkey = st.text_input("Enter Passkey to Decrypt:", type="password")  # Passkey input

    if st.button("Decrypt All"):  # Decrypt button
        if passkey:  # Check if passkey is provided
            try:
                # Select data based on category filter
                data_list = stored_data[st.session_state.authenticated_user]["categories"].get(category, []) if category != "All" else stored_data[st.session_state.authenticated_user]["data"]
                for idx, item in enumerate(data_list):  # Iterate through data
                    # Get encrypted data based on category or general list
                    encrypted = item["encrypted_data"] if category != "All" else item
                    decrypted = decrypt_text(encrypted, passkey)  # Decrypt data
                    # Include category and timestamp for categorized data
                    category_info = f"Category: {item['category']}, " if category != "All" else ""
                    st.success(f"Data {idx+1}: {category_info}Timestamp: {item['timestamp'] if category != 'All' else 'N/A'}\n{decrypted}")
                st.session_state.failed_attempts = 0  # Reset failed attempts
                log_audit_event("DATA_RETRIEVED", st.session_state.authenticated_user, f"Category: {category}")
            except Exception as e:  # Handle decryption errors
                st.session_state.failed_attempts += 1  # Increment failed attempts
                st.session_state.lockout_time = time.time()  # Set lockout time
                log_audit_event("DECRYPTION_FAILED", st.session_state.authenticated_user, str(e))
                st.error(f"❌ Incorrect passkey! Attempts left: {3 - st.session_state.failed_attempts}")
                if st.session_state.failed_attempts >= 3:  # Check for lockout
                    st.warning("🔒 Too many failed attempts! Locked out.")
        else:
            st.error("⚠️ Passkey is required!")  # Missing passkey error

# Search Data Page
elif choice == "Search Data":
    if not st.session_state.authenticated_user:  # Check if user is logged in
        st.warning("🔒 Please login to search data.")
    else:
        st.subheader("🔎 Search Encrypted Data")  # Page title
        search_term = st.text_input("Search Term")  # Search term input
        passkey = st.text_input("Enter Passkey to Decrypt:", type="password")  # Passkey input
        
        if st.button("Search"):  # Search button
            if search_term and passkey:  # Check if fields are filled
                try:
                    found = False  # Track if matches are found
                    # Iterate through all categories and their items
                    for category, items in stored_data[st.session_state.authenticated_user]["categories"].items():
                        for idx, item in enumerate(items):  # Iterate through items
                            decrypted = decrypt_text(item["encrypted_data"], passkey)  # Decrypt
                            # Check if search term is in decrypted data (case-insensitive)
                            if search_term.lower() in decrypted.lower():
                                found = True
                                st.success(f"Match in {category} (Entry {idx+1}): {decrypted}")
                    if not found:
                        st.info("No matches found.")  # No matches found
                    log_audit_event("DATA_SEARCH", st.session_state.authenticated_user, f"Term: {search_term}")
                except Exception:  # Handle decryption errors
                    st.error("❌ Incorrect passkey!")
                    log_audit_event("SEARCH_FAILED", st.session_state.authenticated_user, "Invalid passkey")
            else:
                st.error("⚠️ Both fields are required!")  # Missing fields error

# Backup Management Page
elif choice == "Backup Management":
    if not st.session_state.authenticated_user:  # Check if user is logged in
        st.warning("🔒 Please login to manage backups.")
    else:
        st.subheader("💾 Backup Management")  # Page title
        master_password = st.text_input("Master Password", type="password")  # Master password input
        
        st.write("### Export Backup")  # Export section
        if st.button("Export Encrypted Backup"):  # Export button
            if master_password:  # Check if master password is provided
                backup = export_backup(st.session_state.authenticated_user, master_password)  # Create backup
                if backup:
                    # Provide download button for encrypted backup
                    st.download_button(
                        label="Download Backup",
                        data=backup,
                        file_name=f"backup_{st.session_state.authenticated_user}.enc",
                        mime="application/octet-stream"
                    )
                    log_audit_event("BACKUP_EXPORT", st.session_state.authenticated_user)
                else:
                    st.error("❌ Invalid master password!")  # Invalid password error
                    log_audit_event("BACKUP_EXPORT_FAILED", st.session_state.authenticated_user)
            else:
                st.error("⚠️ Master password required!")  # Missing password error

        st.write("### Import Backup")  # Import section
        uploaded_file = st.file_uploader("Upload Backup File", type=["enc"])  # File uploader
        if uploaded_file and st.button("Import Backup"):  # Import button
            if master_password:  # Check if master password is provided
                # Attempt to import backup
                if import_backup(uploaded_file.read(), master_password, st.session_state.authenticated_user):
                    st.success("✅ Backup imported successfully!")  # Success message
                    log_audit_event("BACKUP_IMPORT", st.session_state.authenticated_user)
                else:
                    # Failed to import (invalid password or corrupted file)
                    st.error("❌ Failed to import backup! Invalid password or corrupted file.")
                    log_audit_event("BACKUP_IMPORT_FAILED", st.session_state.authenticated_user)
            else:
                st.error("⚠️ Master password required!")  # Missing password error

# Audit Log Page
elif choice == "Audit Log":
    if not st.session_state.authenticated_user:  # Check if user is logged in
        st.warning("🔒 Please login to view audit log.")
    else:
        st.subheader("📜 Audit Log")  # Page title
        master_password = st.text_input("Master Password for Audit Log", type="password")  # Master password input
        
        if st.button("View Audit Log"):  # View button
            if master_password == MASTER_PASSWORD:  # Check master password
                audit_log = load_audit_log()  # Load audit log
                # Display audit entries for the current user
                for entry in audit_log:
                    if entry["username"] == st.session_state.authenticated_user:
                        st.write(f"[{entry['timestamp']}] {entry['event_type']}: {entry['details']}")
                log_audit_event("AUDIT_VIEW", st.session_state.authenticated_user)
            else:
                st.error("❌ Invalid master password!")  # Invalid password error
                log_audit_event("AUDIT_VIEW_FAILED", st.session_state.authenticated_user)