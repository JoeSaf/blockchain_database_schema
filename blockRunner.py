from pathlib import Path
import os
import json
import sys
import time
import getpass
import blockchain_databases
from polymorphic_adjuster import BlockAdjuster
from storage import BlockchainStorage

# Global objects that can be imported by other modules
auth_system = None
blockchain = None
adjuster = None

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
    """Initialize the entire blockchain system with proper integration"""
    global auth_system, blockchain
    
    print("\n===== Integrated Blockchain System Setup =====")
    
    # Setup all directories
    setup_directories()
    
    # Initialize centralized chain management
    print("🔧 Setting up centralized chain management...")
    from centralized_chain_management import ChainDirectoryManager
    chain_manager = ChainDirectoryManager()
    
    # Migrate existing files if they exist
    migrated_count = chain_manager.migrate_existing_files()
    if migrated_count > 0:
        print(f"📦 Migrated {migrated_count} files to centralized structure")
    
    # Check for missing database files
    missing_files = check_database_files()
    if missing_files:
        print(f"The following database files are missing: {', '.join(missing_files)}")
        print("These will be created during system initialization.")
    
    # Import and initialize the blockchain system
    from polymorphicblock import initialize_system
    auth_system = initialize_system()
    blockchain = auth_system.blockchain
    
    # Ensure the blockchain has the chain manager
    if not hasattr(blockchain, 'chain_manager'):
        blockchain.chain_manager = chain_manager
        print("🔗 Attached chain manager to blockchain instance")
    
    # Initialize adjuster with proper integration
    from polymorphic_adjuster import BlockAdjuster
    adjuster = BlockAdjuster(blockchain)
    
    # Initialize database folders
    blockchain_databases.initialize_database_folders()
    
    # Verify integration
    print("🔍 Verifying system integration...")
    centralized_path = chain_manager.base_dir
    active_path = chain_manager.get_path('active', 'blockchain_db.json')
    
    print(f"   ✅ Centralized storage: {centralized_path}")
    print(f"   ✅ Active blockchain: {active_path}")
    print(f"   ✅ Quarantine directory: {chain_manager.subdirs['quarantine']}")
    print(f"   ✅ Forensics directory: {chain_manager.subdirs['forensics']}")
    
    print("\n🎉 Integrated blockchain system initialized successfully.")
    print("Please login to continue.")
    
    return auth_system, blockchain

def verify_web_gui_integration():
    """Verify that the web GUI can properly access centralized data"""
    try:
        print("🌐 Verifying web GUI integration...")
        
        # Check if db_gui can import the necessary components
        try:
            from db_gui import security_analyzer, chain_manager
            print("   ✅ Security analyzer integration: OK")
            print("   ✅ Chain manager integration: OK")
        except ImportError as e:
            print(f"   ❌ Import error: {e}")
            return False
        
        # Check if centralized directories exist
        if hasattr(blockchain, 'chain_manager'):
            cm = blockchain.chain_manager
            required_dirs = ['active', 'quarantine', 'forensics', 'fallbacks']
            
            for dir_name in required_dirs:
                if dir_name in cm.subdirs and cm.subdirs[dir_name].exists():
                    print(f"   ✅ {dir_name} directory: {cm.subdirs[dir_name]}")
                else:
                    print(f"   ❌ {dir_name} directory: Missing")
                    return False
        
        print("🌐 Web GUI integration verified successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Web GUI integration check failed: {e}")
        return False


def run_system():
    """Run the blockchain system with enhanced integration"""
    global auth_system, blockchain, adjuster
    
    # Initialize the system if needed
    if not os.path.exists("blockchain_db.json") and not os.path.exists("system_chains/active/blockchain_db.json"):
        auth_system, blockchain = initialize_blockchain_system()
    else:
        # Load existing system with integration
        from polymorphicblock import AuthSystem
        auth_system = AuthSystem()
        blockchain = auth_system.blockchain
        
        # Ensure chain manager is attached
        if not hasattr(blockchain, 'chain_manager'):
            from centralized_chain_management import ChainDirectoryManager
            blockchain.chain_manager = ChainDirectoryManager()
            print("🔗 Attached chain manager to existing blockchain")
        
        from polymorphic_adjuster import BlockAdjuster
        adjuster = BlockAdjuster(blockchain)
        adjuster.start_timer()    
    
    # Verify web GUI integration
    verify_web_gui_integration()
    
    # Authenticate user
    from polymorphicblock import authenticate
    username, user_role, auth_system_new = authenticate()
    
    # If authentication successful, show main menu
    if username:
        # Update global auth_system with the one from authentication
        auth_system = auth_system_new
        
        # Show main menu - pass auth_system to main_menu
        from polymorphicblock import main_menu
        main_menu(username, user_role, auth_system, adjuster)

def start_web_gui():
    """Start the integrated web GUI"""
    try:
        print("\n🌐 Starting integrated web GUI...")
        print("🔧 Initializing security dashboard...")
        
        # Import and run the integrated db_gui
        import subprocess
        import sys
        
        # Run the web GUI in a separate process
        gui_process = subprocess.Popen([
            sys.executable, "db_gui.py"
        ], cwd=os.getcwd())
        
        print("🌐 Web GUI started successfully!")
        print("🔗 Access the security dashboard at: http://localhost:1337/security-dashboard")
        
        return gui_process
        
    except Exception as e:
        print(f"❌ Failed to start web GUI: {e}")
        return None