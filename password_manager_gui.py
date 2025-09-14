import tkinter as tk                            # GUI framework for desktop applications
from tkinter import simpledialog, messagebox    # Pop-up dialogs and message boxes
import random                                   # For generating random passwords
import string                                   # Contains character sets (letters, digits, symbols, etc.)
import csv                                      # For reading/writing CSV files
import os                                       # Operating system interface (file paths, etc..)
import sys                                      # System-specific parameters (for EXE detection)
import pyperclip                                # Copy text to clipboard
from cryptography.fernet import Fernet          # Symmetric encryption
import json                                     # For reading/writing JSON files
import two_factor_auth                          # For hashing the master password
from PIL import Image, ImageTk                  # For displaying QR code images

def resource_path(filename):
    """For bundled files like key.key that are included in the EXE"""
    if hasattr(sys, '_MEIPASS'): # If running from the compiled exe
        # PyInstaller creates a temporary folder '_MEIPASS' with bundled files
        return os.path.join(sys._MEIPASS, filename)
    # If running as normal Python script
    return os.path.abspath(filename)

def get_data_path(filename):
    """For data files (CSV, JSON, PNG) that are created/modified at runtime"""
    if getattr(sys, 'frozen', False):
        # 'frozen' attribute exists when running as EXE
        # Get the directory where the EXE is located
        application_path = os.path.dirname(sys.executable)
    else:
        # Running as script - get the script's directory
        application_path = os.path.dirname(os.path.abspath(__file__))
        
    return os.path.join(application_path, filename)

def load_key():
    """Load the previously generated key (works with embedded exe)"""
    key_path = resource_path("key.key") # Get correct path for key.key
    
    # Check if key file exists
    if not os.path.exists(key_path):
        # Only generate key in development mode
        if not getattr(sys, 'frozen', False):
            key = Fernet.generate_key() # Generate new encryption key
            with open("key.key", "wb") as key_file:
                key_file.write(key) # Save the key to a file
            return key
        else:
            # In EXE mode, key must exist
            raise FileNotFoundError("Encryption key not found...")
        
    # Read and return the key
    with open(key_path, "rb") as file:
        return file.read()
    
def generate_password(length):
    """Generate a random password of specified length."""
    # Create a pool of all possible characters
    characters = string.ascii_letters + string.digits + string.punctuation
    # ascii_letters = 'absc...xyzABC...XYZ'
    # digits = '0123456789'
    # punctuation = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
    
    # Pick random characters from the pool
    password = ''.join(random.choice(characters) for i in range(length))
    return password

def find_website(website, passwords_file):
    """Find a website in the passwords.csv file"""
    # Check if CSV file exists
    if not os.path.isfile(passwords_file):
        return None, -1, [] # Return: (entry, index, all_rows)
    
    with open(passwords_file, 'r') as csvfile:
        reader = csv.DictReader(csvfile) # Read CSV file headers
        rows = list(reader) # Convert to list for indexing
        
        # Search for the website
        for i, row in enumerate(rows):
            if row['website'] == website:
                return row, i, rows # Found: return entry, (i) its index, all rows
            
    return None, -1, rows # Not found: return None, -1 index, all rows

class PasswordManagerGUI(tk.Tk):
    def __init__(self):
        super().__init__() # Initialize the parent tkinter window
        self.title("Password Manager By Yags") # Window title
        self.geometry("400x400") # Window size
        
        # Center window on screen
        self.update_idletasks() # Update window to get correct dimensions
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2) # Calculate center X
        y = (self.winfo_screenheight() // 2) - (height // 2) # Calculate center Y
        self.geometry(f'{width}x{height}+{x}+{y}') # Set position
        
        # Load encryption key
        try:
            self.key = load_key()
            self.fernet = Fernet(self.key) # Create encryption object
        except FileNotFoundError as e:
            messagebox.showerror("Error", str(e))
            self.destroy() # Close app if key not found
            return
        
        # Set file paths for data storage
        self.master_password_file = get_data_path("master_password.json")
        self.passwords_file = get_data_path("passwords.csv")
        self.qr_file = get_data_path("2fa_qr.png")
        
        # Check if this is first run or returning user
        if not os.path.isfile(self.master_password_file):
            self.create_registration_widgets() # First time - register
        else:
            self.create_login_widgets() # Returning user - login
            
def create_registration_widgets(self):
        # Create a frame (container) for registration elemenets
        self.registration_frame = tk.Frame(self)
        self.registration_frame.pack(pady=20) # pady = padding on Y axis
        
        # Master password field
        tk.Label(self.registration_frame, text="Create a Master Password: ").grid(
            row=0, column=0, padx=5, pady=5, sticky='e') # sticky='e' aligns right
        self.reg_password_entry = tk.Entry(self.registration_frame, show="*", width=20)
        # show="*" masks the password input
        self.reg_password_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Confirm password field
        tk.Label(self.registration_frame, text="Confirm Master Password: ").grid(
            row=0, column=1, padx=5, pady=5, sticky='e')
        self.confirm_password_entry = tk.Entry(self.registration_frame, show="*", width=20)
        self.confirm_password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Username for 2FA
        tk.Label(self.registration_frame, text="Username (for 2FA): ").grid(
            row=2, column=0, padx=5, pady=5, sticky='e')
        self.reg_username_entry = tk.Entry(self.registration_frame, width=20)
        self.reg_username_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Register button
        tk.Button(self.registration_frame, text="Register",
                  command=self.register, width=15).grid(row=3, columnspan=2, pady=10)
        # columnspan=2 makes button span across 2 collumns
        
def register(self):
    # Get user inputs
    password = self.reg_password_entry.get()
    confirm_password = self.confirm_password_entry.get()
    username = self.reg_username_entry.get()
    
    # Validation checks
    if password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match!")
        return
    
    if not password:
        messagebox.showerror("Error", "Password cannot be empty!")
        return
    
    if not username:
        messagebox.showerror("Error", "Username cannot be empty!")
        return
    
    # Create secure password hash
    salt = os.urandom(16) # Generate a random 16-byte salt
    # PBKDF2: Password-Based Key Derivation Function 2
    # Makes brute-force attacks harder by adding coputational work
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256', # Hash algorithm
        password.encode(), # Convert password to bytes
        salt, # Random salt (prevents rainbow table attacks)
        100000 # Iterations (makes hashing slow on purpose)
    )
    
    # Generate 2FA secret
    tfa_secret = two_factor_auth.generate_secret()
    
    # Save to JSON file
    try:
        with open(self.master_password_file, 'w') as f:
            json.dump({
                'salt': salt.hex(), # Convert bytes to hex string for JSON
                'password_hash': hashed_password.hex(),
                'tfa_secret': tfa_secret
            }, f)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save master password: {str(e)}")
        return
    
    # Move to 2FA setup
    self.registration_frame.destroy() # Remove registration widgets
    self.setup_2fa(tfa_secret, username)
    
def setup_2fa(self, secret, username):
    self.setup_frame = tk.Frame(self)
    self.setup_frame.pack(pady=20)
    
    # Generate URI for authenticator apps
    # Format: otpauth://totp/PasswordManager:username?secret=XXXXX&issuer=PasswordManager
    uri = two_factor_auth.get_provisioning_uri(secret, username)
    
    try:
        # Create QR code image
        qr_filename = two_factor_auth.generate_qr_code(uri, self.qr_file)
        
        # Load and display QR code
        self.qr_image = Image.open(qr_filename)
        self.qr_photo = ImageTk.PhotoImage(self.qr_image) # Convert for tkinter
        
        tk.Label(self.setup_frame, text="Scan this QR code with your authenticator app",
                 font=("Arial", 10, "bold")).pack(pady=10)
        
        qr_label = tk.Label(self.setup_frame, image=self.qr_photo)
        qr_label.pack(pady=10)
        
        # Show secret for manual entry (If QR scan fails)
        tk.Label(self.setup_frame, text="Secret key (manual entry):",
                 font=("Arial", 9)).pack(pady=5)
        
        secret_text = tk.Text(self.setup_frame, height=2, width=40)
        secret_text.insert(tk.End, secret)
        secret_text.config(state=tk.DISABLED) # Make read-only
        secret_text.pack(pady=5)
        
        tk.Button(self.setup_frame, text="Done",
                  command=self.finish_setup, width=15).pack(pady=10)
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate QR code: {str(e)}")
        self.finish_setup()