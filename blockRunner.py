# blockRunner.py - Updated with Centralized Management Integration

import os
import json
import sys
import time
import getpass

# Try to import centralized management components
try:
    from centralized_chain_management import ChainDirectoryManager
    from compatibility_layer import CompatibilityManager, initialize_compatibility, get_blockchain_path
    CENTRALIZED_AVAILABLE = True
    print("✅ [INIT] Centralized management modules loaded successfully")
except ImportError as e:
    print(f"⚠️  [INIT] Centralized management not available: {str(e)}")
    print("🔄 [INIT] Falling back to legacy mode")
    CENTRALIZED_AVAILABLE = False

# Import core blockchain components
from polymorphicblock import AuthSystem, authenticate, initialize_system, main_menu
import blockchain_databases
from polymorphic_adjuster import BlockAdjuster
from storage import BlockchainStorage

# Global objects that can be imported by other modules
auth_system = None
blockchain = None
adjuster = None

def setup_directories():
    """Set up all necessary directories for the blockchain system"""
    print("\n📁 [SETUP] Initializing directory structure...")
    
    if CENTRALIZED_AVAILABLE:
        # Initialize centralized management
        print("🔄 [SETUP] Setting up centralized file management...")
        migration_performed = initialize_compatibility()
        
        if migration_performed:
            print("✅ [SETUP] File migration completed successfully")
        else:
            print("ℹ️  [SETUP] No files needed migration")
            
        # Get centralized paths
        blockchain_path = get_blockchain_path()
        print(f"📂 [SETUP] Active blockchain path: {blockchain_path}")
        
    else:
        # Create legacy directories
        directories = ["userData", "databases", "security_logs"]
        
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)
                print(f"Created directory: {directory}")
    
    return True

def check_database_files():
    """Check if necessary database files exist"""
    if CENTRALIZED_AVAILABLE:
        # Check centralized locations
        try:
            from compatibility_layer import compatibility_manager
            
            # Check for main blockchain file
            blockchain_path = compatibility_manager.get_file_path('blockchain_db.json', 'active')
            storage_path = compatibility_manager.get_file_path('blockStorage.json', 'active')
            
            missing_files = []
            
            if not blockchain_path.exists():
                missing_files.append('blockchain_db.json')
            if not storage_path.exists():
                missing_files.append('blockStorage.json')
                
            return missing_files
            
        except Exception as e:
            print(f"⚠️  [CHECK] Error checking centralized files: {str(e)}")
            return ["blockchain_db.json", "blockStorage.json"]  # Assume missing
    else:
        # Check legacy locations
        database_files = ["blockchain_db.json", "blockStorage.json"]
        missing_files = []
        
        for file in database_files:
            if not os.path.exists(file):
                missing_files.append(file)
        
        return missing_files

def initialize_blockchain_system():
    """Initialize the entire blockchain system with centralized management support"""
    global auth_system, blockchain
    
    print("\n===== Blockchain System Setup =====")
    
    # Step 1: Setup directories (centralized or legacy)
    setup_success = setup_directories()
    if not setup_success:
        print("❌ [ERROR] Failed to setup directories")
        return None, None
    
    # Step 2: Check for missing database files
    missing_files = check_database_files()
    if missing_files:
        print(f"📝 [INFO] Missing files will be created: {', '.join(missing_files)}")
    else:
        print("✅ [INFO] All required files found")
    
    # Step 3: Initialize the blockchain system and get auth_system
    try:
        auth_system = initialize_system()
        blockchain = auth_system.blockchain
        
        # Initialize adjuster with enhanced error handling
        try:
            adjuster = BlockAdjuster(blockchain)
            print("✅ [ADJUSTER] Block adjuster initialized")
        except Exception as e:
            print(f"⚠️  [ADJUSTER] Failed to initialize block adjuster: {str(e)}")
            adjuster = None
        
        # Initialize database folders
        blockchain_databases.initialize_database_folders()
        
        # Show system status
        show_initialization_status()
        
        print("\n✅ [SUCCESS] Blockchain system initialized successfully.")
        print("Please login to continue.")
        
        return auth_system, blockchain
        
    except Exception as e:
        print(f"❌ [ERROR] Failed to initialize blockchain system: {str(e)}")
        print("🔄 [FALLBACK] Attempting recovery...")
        
        # Try to recover or create minimal system
        try:
            auth_system = AuthSystem()
            blockchain = auth_system.blockchain
            return auth_system, blockchain
        except Exception as recovery_error:
            print(f"❌ [FATAL] Recovery failed: {str(recovery_error)}")
            return None, None

def show_initialization_status():
    """Display detailed initialization status"""
    print("\n📊 [STATUS] System Initialization Summary")
    print("=" * 50)
    
    if CENTRALIZED_AVAILABLE:
        try:
            from compatibility_layer import compatibility_manager
            
            print("✅ Centralized Management: ACTIVE")
            print(f"📂 Base Directory: {compatibility_manager.chain_manager.base_dir}")
            
            # Show file locations
            blockchain_path = compatibility_manager.get_file_path('blockchain_db.json', 'active')
            storage_path = compatibility_manager.get_file_path('blockStorage.json', 'active')
            
            print(f"🔗 Main Blockchain: {blockchain_path}")
            print(f"🔗 Database Storage: {storage_path}")
            
            # Check for legacy compatibility
            legacy_files = 0
            for legacy_file in ['blockchain_db.json', 'blockStorage.json']:
                if os.path.exists(legacy_file):
                    legacy_files += 1
            
            if legacy_files > 0:
                print(f"🔗 Legacy Compatibility: {legacy_files} files maintained")
            else:
                print("✅ Legacy Cleanup: Complete")
                
        except Exception as e:
            print(f"⚠️  Centralized Management: ERROR - {str(e)}")
            
    else:
        print("⚠️  Centralized Management: DISABLED")
        print("📂 File Structure: Legacy Mode")
        
        # Show legacy file status
        blockchain_exists = os.path.exists("blockchain_db.json")
        storage_exists = os.path.exists("blockStorage.json")
        
        print(f"🔗 Main Blockchain: {'✅ Found' if blockchain_exists else '📝 Will be created'}")
        print(f"🔗 Database Storage: {'✅ Found' if storage_exists else '📝 Will be created'}")
    
    print("=" * 50)

def run_system():
    """Run the blockchain system with enhanced error handling and status reporting"""
    global auth_system, blockchain, adjuster
    
    print("🚀 [START] Starting blockchain system...")
    
    # Check if system needs initialization
    needs_init = False
    
    if CENTRALIZED_AVAILABLE:
        try:
            from compatibility_layer import compatibility_manager
            blockchain_path = compatibility_manager.get_file_path('blockchain_db.json', 'active')
            needs_init = not blockchain_path.exists()
        except Exception as e:
            print(f"⚠️  [CHECK] Error checking centralized blockchain: {str(e)}")
            needs_init = True
    else:
        needs_init = not os.path.exists("blockchain_db.json")
    
    # Initialize or load system
    if needs_init:
        print("🔄 [INIT] Initializing new blockchain system...")
        auth_system, blockchain = initialize_blockchain_system()
        
        if not auth_system or not blockchain:
            print("❌ [FATAL] Failed to initialize blockchain system")
            return False
            
    else:
        print("📖 [LOAD] Loading existing blockchain system...")
        try:
            # Load existing system
            auth_system = AuthSystem()
            blockchain = auth_system.blockchain
            
            # Initialize adjuster
            try:
                adjuster = BlockAdjuster(blockchain)
                adjuster.start_timer()
                print("✅ [ADJUSTER] Block adjuster started with timer")
            except Exception as e:
                print(f"⚠️  [ADJUSTER] Failed to start adjuster: {str(e)}")
                adjuster = None
                
            print("✅ [LOAD] System loaded successfully")
            
        except Exception as e:
            print(f"❌ [LOAD] Failed to load existing system: {str(e)}")
            print("🔄 [RECOVERY] Attempting to initialize new system...")
            
            auth_system, blockchain = initialize_blockchain_system()
            if not auth_system or not blockchain:
                print("❌ [FATAL] Recovery initialization failed")
                return False
    
    # Verify system integrity before proceeding
    try:
        integrity_check = blockchain.is_chain_valid()
        if integrity_check:
            print("✅ [INTEGRITY] Blockchain integrity verified")
        else:
            print("⚠️  [INTEGRITY] Blockchain integrity issues detected - fallback procedures may have been triggered")
    except Exception as e:
        print(f"⚠️  [INTEGRITY] Error during integrity check: {str(e)}")
    
    # Authenticate user
    print("\n🔐 [AUTH] User authentication required...")
    try:
        username, user_role, auth_system_new = authenticate()
        
        # If authentication successful, show main menu
        if username:
            # Update global auth_system with the one from authentication
            auth_system = auth_system_new
            
            print(f"✅ [AUTH] Authentication successful for {username} ({user_role})")
            
            # Show main menu - pass auth_system to main_menu
            main_menu(username, user_role, auth_system, adjuster)
            return True
        else:
            print("❌ [AUTH] Authentication failed")
            return False
            
    except Exception as e:
        print(f"❌ [AUTH] Authentication error: {str(e)}")
        return False

def show_system_status():
    """Display comprehensive system status for diagnostics"""
    print("\n" + "="*60)
    print("🔍 BLOCKCHAIN SYSTEM STATUS")
    print("="*60)
    
    # Basic system info
    print(f"🐍 Python Version: {sys.version}")
    print(f"📂 Working Directory: {os.getcwd()}")
    
    # Centralized management status
    if CENTRALIZED_AVAILABLE:
        try:
            from compatibility_layer import compatibility_manager
            print("✅ Centralized Management: ACTIVE")
            print(f"📁 Base Directory: {compatibility_manager.chain_manager.base_dir}")
            
            # File counts by category
            for name, path in compatibility_manager.chain_manager.subdirs.items():
                if path.exists():
                    file_count = len(list(path.glob('*.json')))
                    print(f"   ├─ {name}: {file_count} files")
                else:
                    print(f"   ├─ {name}: not created")
                    
        except Exception as e:
            print(f"❌ Centralized Management: ERROR - {str(e)}")
    else:
        print("⚠️  Centralized Management: DISABLED")
    
    # Blockchain status
    if blockchain:
        print(f"\n⛓️  Blockchain Status:")
        print(f"   ├─ Blocks: {len(blockchain.chain)}")
        print(f"   ├─ Valid: {blockchain.is_chain_valid()}")
        print(f"   └─ Latest: Block #{blockchain.get_latest_block().index}")
    else:
        print("\n❌ Blockchain: NOT LOADED")
    
    # Database status
    if auth_system and hasattr(auth_system, 'db_manager'):
        try:
            db_status = auth_system.db_manager.get_system_status()
            print(f"\n🗄️  Database Status:")
            print(f"   ├─ Databases: {db_status['total_databases']}")
            print(f"   ├─ Chain Length: {db_status['database_chain_length']}")
            print(f"   └─ Chain Valid: {db_status['database_chain_valid']}")
        except Exception as e:
            print(f"\n❌ Database Status: ERROR - {str(e)}")
    else:
        print(f"\n⚠️  Database Status: NOT INITIALIZED")
    
    print("="*60)

def cleanup_system():
    """Clean up system resources and save state"""
    print("\n🧹 [CLEANUP] Shutting down blockchain system...")
    
    try:
        # Save blockchain state if available
        if blockchain:
            blockchain.save_chain()
            print("✅ [CLEANUP] Blockchain state saved")
        
        # Stop adjuster if running
        if adjuster:
            print("✅ [CLEANUP] Block adjuster stopped")
        
        # Additional cleanup tasks
        print("✅ [CLEANUP] System cleanup completed")
        
    except Exception as e:
        print(f"⚠️  [CLEANUP] Error during cleanup: {str(e)}")

if __name__ == "__main__":
    try:
        # Add command line options
        if len(sys.argv) > 1:
            if sys.argv[1] == "--status":
                # Initialize minimal system for status check
                if CENTRALIZED_AVAILABLE:
                    initialize_compatibility()
                show_system_status()
                sys.exit(0)
            elif sys.argv[1] == "--migrate":
                # Force migration
                if CENTRALIZED_AVAILABLE:
                    print("🔄 [MIGRATE] Forcing file migration...")
                    initialize_compatibility()
                    print("✅ [MIGRATE] Migration completed")
                else:
                    print("❌ [MIGRATE] Centralized management not available")
                sys.exit(0)
            elif sys.argv[1] == "--help":
                print("Blockchain System Options:")
                print("  --status   : Show system status")
                print("  --migrate  : Force file migration")
                print("  --help     : Show this help")
                sys.exit(0)
        
        # Run main system
        success = run_system()
        
        if success:
            cleanup_system()
            print("👋 [EXIT] Blockchain system shutdown successfully")
        else:
            print("❌ [EXIT] Blockchain system encountered errors")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⚠️  [INTERRUPT] System interrupted by user")
        cleanup_system()
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ [FATAL] Unexpected error: {str(e)}")
        cleanup_system()
        sys.exit(1)