import os
import json
import sys
import time
import getpass
from polymorphicblock import AuthSystem, authenticate, initialize_system, main_menu
import blockchain_databases

def setup_directories():
    """Set up all necessary directories for the blockchain system"""
    # Create main directories
    directories = ["userData", "databases", "security_logs"]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")
            
    return True

def check_database_files():
    """Check if necessary database files exist"""
    database_files = ["blockchain_db.json", "blockStorage.json"]
    missing_files = []
    
    for file in database_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    return missing_files

def initialize_blockchain_system():
    """Initialize the entire blockchain system"""
    print("\n===== Blockchain System Setup =====")
    
    # Setup all directories
    setup_directories()
    
    # Check for missing database files
    missing_files = check_database_files()
    if missing_files:
        print(f"The following database files are missing: {', '.join(missing_files)}")
        print("These will be created during system initialization.")
    
    # Initialize the blockchain system
    initialize_system()
    
    # Initialize database folders
    blockchain_databases.initialize_database_folders()
    
    print("\nBlockchain system initialized successfully.")
    print("Please login to continue.")

def run_system():
    """Run the blockchain system"""
    # Initialize the system if needed
    if not os.path.exists("blockchain_db.json"):
        initialize_blockchain_system()
    
    # Authenticate user
    username, user_role = authenticate()
    
    # If authentication successful, show main menu
    if username:
        main_menu(username, user_role)

if __name__ == "__main__":
    run_system()