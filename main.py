import sqlite3
import hashlib
import getpass
from cryptography.fernet import Fernet
import os
import base64

# Initialize database connection
conn = sqlite3.connect('passwords.db')
c = conn.cursor()

# Create tables if they don't exist
c.execute('''CREATE TABLE IF NOT EXISTS passwords 
             (id INTEGER PRIMARY KEY, website TEXT, username TEXT, password TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS master_password 
             (id INTEGER PRIMARY KEY, hash TEXT)''')
conn.commit()

# Encryption setup
def generate_key(master_password):
    # Derive a consistent key from the master password
    return base64.urlsafe_b64encode(hashlib.sha256(master_password.encode()).digest()[:32])

def encrypt_password(password, master_password):
    key = generate_key(master_password)
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password, master_password):
    key = generate_key(master_password)
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()

# Password hashing
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Master password functions
def set_master_password():
    if master_password_exists():
        print("Master password already set!")
        return
    
    password = getpass.getpass("Set master password: ")
    confirm = getpass.getpass("Confirm master password: ")
    
    if password != confirm:
        print("Passwords don't match!")
        return
    
    hashed = hash_password(password)
    c.execute("INSERT INTO master_password (hash) VALUES (?)", (hashed,))
    conn.commit()
    print("Master password set successfully!")

def verify_master_password():
    password = getpass.getpass("Enter master password: ")
    c.execute("SELECT hash FROM master_password LIMIT 1")
    result = c.fetchone()
    
    if not result:
        print("No master password set!")
        return False
    
    return hash_password(password) == result[0]

def master_password_exists():
    c.execute("SELECT COUNT(*) FROM master_password")
    return c.fetchone()[0] > 0

# Password management functions
def add_password():
    if not master_password_exists():
        print("Please set a master password first!")
        return
    
    if not verify_master_password():
        print("Invalid master password!")
        return
    
    website = input("Enter website: ")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    master_pwd = getpass.getpass("Enter master password to encrypt: ")
    
    encrypted_password = encrypt_password(password, master_pwd)
    
    c.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)",
              (website, username, encrypted_password))
    conn.commit()
    print("Password added successfully!")

def get_password():
    if not master_password_exists():
        print("No passwords stored yet!")
        return
    
    if not verify_master_password():
        print("Invalid master password!")
        return
    
    website = input("Enter website: ")
    username = input("Enter username: ")
    
    c.execute("SELECT password FROM passwords WHERE website = ? AND username = ?",
              (website, username))
    result = c.fetchone()
    
    if result:
        master_pwd = getpass.getpass("Enter master password to decrypt: ")
        try:
            decrypted_password = decrypt_password(result[0], master_pwd)
            print(f"Password for {website} ({username}): {decrypted_password}")
        except:
            print("Invalid master password or corrupted data!")
    else:
        print("Password not found!")

def update_password():
    if not master_password_exists():
        print("No passwords stored yet!")
        return
    
    if not verify_master_password():
        print("Invalid master password!")
        return
    
    website = input("Enter website: ")
    username = input("Enter username: ")
    
    c.execute("SELECT id FROM passwords WHERE website = ? AND username = ?",
              (website, username))
    result = c.fetchone()
    
    if not result:
        print("Password entry not found!")
        return
    
    new_password = getpass.getpass("Enter new password: ")
    master_pwd = getpass.getpass("Enter master password to encrypt: ")
    
    encrypted_password = encrypt_password(new_password, master_pwd)
    
    c.execute("UPDATE passwords SET password = ? WHERE id = ?",
              (encrypted_password, result[0]))
    conn.commit()
    print("Password updated successfully!")

def delete_password():
    if not master_password_exists():
        print("No passwords stored yet!")
        return
    
    if not verify_master_password():
        print("Invalid master password!")
        return
    
    website = input("Enter website: ")
    username = input("Enter username: ")
    
    c.execute("DELETE FROM passwords WHERE website = ? AND username = ?",
              (website, username))
    conn.commit()
    
    if c.rowcount > 0:
        print("Password deleted successfully!")
    else:
        print("Password not found!")

def list_all_entries():
    if not master_password_exists():
        print("No passwords stored yet!")
        return
    
    if not verify_master_password():
        print("Invalid master password!")
        return
    
    c.execute("SELECT website, username FROM passwords")
    results = c.fetchall()
    
    if not results:
        print("No passwords stored yet!")
        return
    
    print("\nStored passwords:")
    for idx, (website, username) in enumerate(results, 1):
        print(f"{idx}. {website} - {username}")

# Main menu
def main_menu():
    while True:
        print("\n=== Password Manager ===")
        if not master_password_exists():
            print("1. Set master password")
        else:
            print("1. Add password")
            print("2. Get password")
            print("3. Update password")
            print("4. Delete password")
            print("5. List all entries")
        print("0. Exit")
        
        choice = input("Enter choice: ")
        
        if not master_password_exists():
            if choice == '1':
                set_master_password()
            elif choice == '0':
                break
            else:
                print("Invalid choice!")
        else:
            if choice == '1':
                add_password()
            elif choice == '2':
                get_password()
            elif choice == '3':
                update_password()
            elif choice == '4':
                delete_password()
            elif choice == '5':
                list_all_entries()
            elif choice == '0':
                break
            else:
                print("Invalid choice!")

    conn.close()
    print("Goodbye!")

if __name__ == "__main__":
    main_menu()