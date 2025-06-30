#!/usr/bin/env python3
"""
Blockchain Database System Startup Script
Fixes circular import issues and ensures proper initialization
"""

import os
import sys
import time
import subprocess

def check_dependencies():
    """Check if required dependencies are available"""
    required_modules = [
        'flask',
        'cryptography',
        'pathlib'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"❌ Missing required modules: {', '.join(missing_modules)}")
        print("Please install them using: pip install flask cryptography")
        return False
    
    return True

def check_files():
    """Check if required files exist"""
    required_files = [
        'polymorphicblock.py',
        'blockchain_databases.py',
        'polymorphic_adjuster.py',
        'storage.py',
        'centralized_chain_management.py'
    ]
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print(f"❌ Missing required files: {', '.join(missing_files)}")
        return False
    
    return True

def setup_directories():
    """Set up necessary directories"""
    directories = [
        "userData",
        "databases", 
        "system_chains",
        "system_chains/active",
        "system_chains/quarantine",
        "system_chains/forensics",
        "system_chains/security_logs",
        "system_chains/fallbacks",
        "system_chains/backups"
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"📁 Created directory: {directory}")

def start_console_mode():
    """Start the console-based blockchain system"""
    try:
        print("🔧 Starting Console Mode...")
        
        # Import without circular dependencies
        from polymorphicblock import initialize_system, authenticate, main_menu
        from polymorphic_adjuster import BlockAdjuster
        
        # Initialize the system
        auth_system = initialize_system()
        adjuster = BlockAdjuster(auth_system.blockchain)
        
        # Authenticate user
        username, user_role, auth_system = authenticate()
        
        # If authentication successful, show main menu
        if username:
            main_menu(username, user_role, auth_system, adjuster)
        else:
            print("❌ Authentication failed. Exiting...")
            
    except Exception as e:
        print(f"❌ Error starting console mode: {e}")
        import traceback
        traceback.print_exc()

def start_web_gui():
    """Start the web GUI mode"""
    try:
        print("🌐 Starting Web GUI Mode...")
        
        # Run the web GUI directly
        subprocess.run([sys.executable, "db_gui.py"])
        
    except Exception as e:
        print(f"❌ Error starting web GUI: {e}")
        import traceback
        traceback.print_exc()

def main():
    """Main startup function"""
    print("🚀 Blockchain Database System Startup")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        return
    
    # Check required files
    if not check_files():
        return
    
    # Setup directories
    setup_directories()
    
    # Ask user for mode
    print("\nSelect startup mode:")
    print("1. Console Mode (Command line interface)")
    print("2. Web GUI Mode (Browser interface)")
    print("3. Exit")
    
    try:
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            start_console_mode()
        elif choice == "2":
            start_web_gui()
        elif choice == "3":
            print("👋 Goodbye!")
        else:
            print("❌ Invalid choice. Please select 1, 2, or 3.")
            
    except KeyboardInterrupt:
        print("\n👋 Shutdown requested. Goodbye!")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()