import json
import os
import time
import shutil
from pathlib import Path

from polymorphicblock import Block

class ChainDirectoryManager:
    """
    Centralized management for all blockchain-related files and directories
    """
    
    def __init__(self, base_dir="system_chains"):
        self.base_dir = Path(base_dir)
        self.setup_directory_structure()
    
    def setup_directory_structure(self):
        """
        Create the centralized directory structure for all chain files
        """
        print(f"\n📁 [SETUP] Creating centralized chain directory structure...")
        
        # Main system_chains directory
        self.base_dir.mkdir(exist_ok=True)
        
        # Subdirectories for different types of chains
        self.subdirs = {
            'active': self.base_dir / 'active',           # Current active blockchain
            'fallbacks': self.base_dir / 'fallbacks',     # Fallback databases
            'quarantine': self.base_dir / 'quarantine',   # Quarantined/infected blocks
            'backups': self.base_dir / 'backups',         # Chain backups
            'forensics': self.base_dir / 'forensics',     # Forensic analysis data
            'archives': self.base_dir / 'archives',       # Historical chains
            'temp': self.base_dir / 'temp'                # Temporary processing files
        }
        
        # Create all subdirectories
        for subdir_name, subdir_path in self.subdirs.items():
            subdir_path.mkdir(exist_ok=True)
            print(f"  ✅ Created: {subdir_path}")
        
        # Create info file about the directory structure
        self.create_directory_info()
        
        print(f"📁 [COMPLETE] Chain directory structure ready at: {self.base_dir.absolute()}")
    
    def create_directory_info(self):
        """Create an info file explaining the directory structure"""
        info = {
            "created_at": time.time(),
            "created_timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "description": "Centralized blockchain file management system",
            "directory_structure": {
                "active": "Current active blockchain files",
                "fallbacks": "Fallback databases created during security events",
                "quarantine": "Quarantined/infected blocks for forensic analysis",
                "backups": "Regular chain backups and snapshots",
                "forensics": "Detailed forensic analysis and security reports",
                "archives": "Historical blockchain versions and migrations",
                "temp": "Temporary files during processing operations"
            },
            "file_naming_conventions": {
                "active_chain": "blockchain_db.json",
                "fallback": "enhanced_fallback_db_{timestamp}.json",
                "quarantine": "quarantined_blocks_{timestamp}.json",
                "backup": "backup_blockchain_{timestamp}.json",
                "forensic": "forensic_report_{timestamp}.json"
            }
        }
        
        info_file = self.base_dir / "directory_info.json"
        with open(info_file, 'w') as f:
            json.dump(info, f, indent=4)
    
    def get_path(self, file_type, filename=None, timestamp=None):
        """
        Get the appropriate path for different types of chain files
        
        Args:
            file_type: Type of file ('active', 'fallback', 'quarantine', etc.)
            filename: Optional custom filename
            timestamp: Optional timestamp for file naming
        
        Returns:
            Path object for the file
        """
        if timestamp is None:
            timestamp = int(time.time())
        
        base_path = self.subdirs.get(file_type, self.base_dir)
        
        if filename:
            return base_path / filename
        
        # Default naming conventions
        default_names = {
            'active': 'blockchain_db.json',
            'fallback': f'enhanced_fallback_db_{timestamp}.json',
            'quarantine': f'quarantined_blocks_{timestamp}.json',
            'backup': f'backup_blockchain_{timestamp}.json',
            'forensic': f'forensic_report_{timestamp}.json',
            'clean_chain': f'clean_blockchain_db_{timestamp}.json'
        }
        
        filename = default_names.get(file_type, f'{file_type}_{timestamp}.json')
        return base_path / filename
    
    def migrate_existing_files(self):
        """
        Migrate existing blockchain files to the new directory structure
        """
        print(f"\n🔄 [MIGRATION] Moving existing files to centralized structure...")
        
        # Files to migrate and their destinations
        migration_map = {
            'blockchain_db.json': ('active', 'blockchain_db.json'),
            'fallback_db.json': ('fallbacks', None),  # Will be renamed with timestamp
            'blockStorage.json': ('active', 'blockStorage.json'),
        }
        
        # Find and migrate files
        current_dir = Path('.')
        migrated_count = 0
        
        for old_file, (dest_type, new_name) in migration_map.items():
            old_path = current_dir / old_file
            
            if old_path.exists():
                if new_name is None:
                    # Generate timestamped name for legacy files
                    file_stat = old_path.stat()
                    timestamp = int(file_stat.st_mtime)
                    new_name = f'legacy_{old_file.replace(".json", "")}_{timestamp}.json'
                
                new_path = self.get_path(dest_type, new_name)
                
                try:
                    shutil.move(str(old_path), str(new_path))
                    print(f"  ✅ Migrated: {old_file} → {new_path}")
                    migrated_count += 1
                except Exception as e:
                    print(f"  ❌ Failed to migrate {old_file}: {str(e)}")
        
        # Look for other chain-related files with patterns
        patterns = [
            'enhanced_fallback_*.json',
            'quarantined_blocks_*.json',
            'clean_blockchain_*.json',
            'fallback_db_*.json'
        ]
        
        for pattern in patterns:
            for file_path in current_dir.glob(pattern):
                try:
                    if 'fallback' in file_path.name:
                        dest_path = self.subdirs['fallbacks'] / file_path.name
                    elif 'quarantined' in file_path.name:
                        dest_path = self.subdirs['quarantine'] / file_path.name
                    elif 'clean' in file_path.name:
                        dest_path = self.subdirs['backups'] / file_path.name
                    else:
                        dest_path = self.subdirs['archives'] / file_path.name
                    
                    shutil.move(str(file_path), str(dest_path))
                    print(f"  ✅ Migrated: {file_path.name} → {dest_path}")
                    migrated_count += 1
                except Exception as e:
                    print(f"  ❌ Failed to migrate {file_path.name}: {str(e)}")
        
        print(f"🔄 [MIGRATION COMPLETE] Moved {migrated_count} files to centralized structure")
        return migrated_count
    
    def create_backup(self, source_file=None):
        """Create a timestamped backup of the current active chain"""
        if source_file is None:
            source_file = self.get_path('active')
        
        source_path = Path(source_file)
        if not source_path.exists():
            print(f"❌ Source file {source_path} does not exist")
            return None
        
        backup_path = self.get_path('backup')
        
        try:
            shutil.copy2(str(source_path), str(backup_path))
            print(f"💾 [BACKUP] Created: {backup_path}")
            return backup_path
        except Exception as e:
            print(f"❌ [BACKUP FAILED] {str(e)}")
            return None
    
    def list_files(self, file_type=None):
        """List all files in the specified category or all categories"""
        if file_type and file_type in self.subdirs:
            dirs_to_check = {file_type: self.subdirs[file_type]}
        else:
            dirs_to_check = self.subdirs
        
        print(f"\n📋 [FILE LISTING] Chain directory contents:")
        print("=" * 60)
        
        total_files = 0
        for dir_name, dir_path in dirs_to_check.items():
            files = list(dir_path.glob('*.json'))
            total_files += len(files)
            
            print(f"\n📁 {dir_name.upper()} ({len(files)} files):")
            print(f"   Location: {dir_path}")
            
            if files:
                for file_path in sorted(files):
                    file_stat = file_path.stat()
                    size_kb = file_stat.st_size / 1024
                    modified = time.strftime('%Y-%m-%d %H:%M:%S', 
                                           time.localtime(file_stat.st_mtime))
                    print(f"   ├─ {file_path.name} ({size_kb:.1f} KB, {modified})")
            else:
                print("   └─ (empty)")
        
        print("=" * 60)
        print(f"📊 Total files: {total_files}")
        return total_files

# Enhanced Blockchain class with centralized file management
class EnhancedBlockchainWithCentralizedStorage:
    """
    Enhanced Blockchain class that uses centralized directory management
    """
    
    def __init__(self):
        # Initialize directory manager
        self.chain_manager = ChainDirectoryManager()
        
        # Migrate existing files on first run
        self.chain_manager.migrate_existing_files()
        
        # Set up blockchain with centralized paths
        self.chain = []
        self.active_chain_path = self.chain_manager.get_path('active')
        
        # Load or create blockchain
        if self.active_chain_path.exists():
            try:
                self.load_chain()
            except Exception as e:
                print(f"Error loading blockchain: {e}")
                print("Creating new blockchain with genesis block.")
                self.chain = [self.create_genesis_block()]
                self.save_chain()
        else:
            self.chain = [self.create_genesis_block()]
            self.save_chain()
    
    def save_chain(self):
        """Save blockchain to centralized active directory"""
        # Create backup before saving new version
        if self.active_chain_path.exists():
            self.chain_manager.create_backup(self.active_chain_path)
        
        # Save to active location
        with open(self.active_chain_path, "w") as f:
            json.dump([block.to_dict() for block in self.chain], f, indent=4)
        
        print(f"💾 [SAVE] Blockchain saved to: {self.active_chain_path}")
    
    def load_chain(self):
        """Load blockchain from centralized active directory"""
        with open(self.active_chain_path, "r") as f:
            chain_data = json.load(f)
            self.chain = []
            for block_data in chain_data:
                block = Block(
                    block_data["index"],
                    block_data["timestamp"],
                    block_data["data"],
                    block_data["previous_hash"]
                )
                block.hash = block_data["hash"]
                self.chain.append(block)
        
        print(f"📖 [LOAD] Blockchain loaded from: {self.active_chain_path}")
    
    def _create_enhanced_fallback_response(self, infected_blocks):
        """
        Enhanced fallback response using centralized file management
        """
        print("\n🛡️  [QUARANTINE PROTOCOL] Creating centralized fallback chain...")
        print("=" * 70)
        
        timestamp = int(time.time())
        infected_ids = [block_info["block_id"] for block_info in infected_blocks]
        
        # Step 1: Separate clean blocks from infected blocks
        clean_blocks = []
        quarantined_blocks = []
        
        # Always preserve genesis block
        clean_blocks.append(self.chain[0])
        print(f"✅ Block #0 (Genesis) - PRESERVED")
        
        # Process remaining blocks
        for block in self.chain[1:]:
            if block.index in infected_ids:
                quarantined_blocks.append(block)
                print(f"🚫 Block #{block.index} - QUARANTINED ({block.data.get('action', 'unknown')})")
            else:
                clean_blocks.append(block)
                print(f"✅ Block #{block.index} - CLEAN ({block.data.get('action', 'unknown')})")
        
        # Step 2: Rebuild hash chain for clean blocks
        print(f"\n🔧 [REBUILD] Reconstructing clean hash chain...")
        for i in range(1, len(clean_blocks)):
            clean_blocks[i].index = i
            clean_blocks[i].previous_hash = clean_blocks[i-1].hash
            clean_blocks[i].hash = clean_blocks[i].calculate_hash()
            print(f"🔗 Block #{i} - Hash chain rebuilt")
        
        # Step 3: Extract users from clean chain only
        clean_users = {}
        for block in clean_blocks:
            if block.data.get("action") == "register":
                username = block.data.get("username")
                if username:
                    clean_users[username] = {
                        "role": block.data.get("role", "user"),
                        "public_key": block.data.get("public_key"),
                        "private_key": block.data.get("private_key"),
                        "migrated_at": time.time(),
                        "source_block": block.index
                    }
        
        # Step 4: Create comprehensive fallback data
        fallback_data = {
            "created_at": time.time(),
            "breach_reason": "Enhanced infection detection and quarantine protocol",
            "scan_timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            "infected_blocks_count": len(infected_blocks),
            "infected_block_ids": infected_ids,
            "infected_block_details": infected_blocks,
            "original_chain_length": len(self.chain),
            "clean_chain_length": len(clean_blocks),
            "quarantined_blocks_count": len(quarantined_blocks),
            "users": clean_users,
            "storage_location": str(self.chain_manager.base_dir),
            "file_paths": {
                "fallback_db": f"fallbacks/enhanced_fallback_db_{timestamp}.json",
                "quarantine_data": f"quarantine/quarantined_blocks_{timestamp}.json",
                "forensic_report": f"forensics/forensic_report_{timestamp}.json"
            }
        }
        
        # Step 5: Save files to centralized locations
        
        # Save enhanced fallback database
        fallback_path = self.chain_manager.get_path('fallback', timestamp=timestamp)
        with open(fallback_path, "w") as f:
            json.dump(fallback_data, f, indent=4)
        
        # Save quarantined blocks for forensic analysis
        quarantine_path = self.chain_manager.get_path('quarantine', timestamp=timestamp)
        with open(quarantine_path, "w") as f:
            json.dump({
                "quarantine_timestamp": time.time(),
                "quarantine_reason": "Blockchain infection detected",
                "infected_blocks": infected_blocks,
                "quarantined_block_data": [block.to_dict() for block in quarantined_blocks]
            }, f, indent=4)
        
        # Save detailed forensic report
        forensic_path = self.chain_manager.get_path('forensic', timestamp=timestamp)
        with open(forensic_path, "w") as f:
            json.dump({
                "forensic_timestamp": time.time(),
                "analysis_type": "Blockchain Infection Analysis",
                "summary": {
                    "total_blocks_analyzed": len(self.chain),
                    "infected_blocks_found": len(infected_blocks),
                    "clean_blocks_preserved": len(clean_blocks),
                    "users_migrated": len(clean_users)
                },
                "infection_details": infected_blocks,
                "quarantine_actions": [
                    f"Block #{bid} quarantined" for bid in infected_ids
                ],
                "recovery_actions": [
                    "Clean chain reconstructed",
                    "Hash links rebuilt", 
                    "User data migrated",
                    "Active chain updated"
                ],
                "file_locations": {
                    "fallback_database": str(fallback_path),
                    "quarantined_blocks": str(quarantine_path),
                    "updated_active_chain": str(self.active_chain_path)
                }
            }, f, indent=4)
        
        # Save clean chain as new active blockchain
        clean_chain_backup = self.chain_manager.get_path('backups', f'clean_blockchain_db_{timestamp}.json')
        with open(clean_chain_backup, "w") as f:
            json.dump([block.to_dict() for block in clean_blocks], f, indent=4)
        
        # Step 6: Replace current chain with clean chain
        self.chain = clean_blocks
        self.save_chain()  # This will save to active directory and create backup
        
        # Step 7: Summary report
        print("\n🎉 [QUARANTINE COMPLETE] System successfully sanitized!")
        print("=" * 70)
        print(f"📁 Centralized storage location: {self.chain_manager.base_dir}")
        print(f"📄 Fallback database: {fallback_path.name}")
        print(f"🚫 Quarantine data: {quarantine_path.name}")
        print(f"🔍 Forensic report: {forensic_path.name}")
        print(f"💾 Clean chain backup: {clean_chain_backup.name}")
        print(f"📊 Statistics:")
        print(f"   ├─ Original chain: {fallback_data['original_chain_length']} blocks")
        print(f"   ├─ Clean chain: {fallback_data['clean_chain_length']} blocks")
        print(f"   ├─ Quarantined: {fallback_data['quarantined_blocks_count']} blocks")
        print(f"   └─ Users preserved: {len(clean_users)}")
        
        print(f"\n✅ Active blockchain updated with clean chain")
        print(f"🚫 Infected blocks stored in quarantine directory")
        print(f"🛡️  System integrity restored with centralized management")
        
        return {
            'fallback_path': fallback_path,
            'quarantine_path': quarantine_path,
            'forensic_path': forensic_path,
            'clean_backup_path': clean_chain_backup
        }

# Integration patch for existing polymorphicblock.py
INTEGRATION_PATCH = '''
# Add these imports at the top of polymorphicblock.py
from pathlib import Path
import shutil

# Replace the BLOCKCHAIN_DB constant
CHAIN_MANAGER = ChainDirectoryManager()
BLOCKCHAIN_DB = str(CHAIN_MANAGER.get_path('active'))

# Update the Blockchain class __init__ method:
def __init__(self):
    global CHAIN_MANAGER
    self.chain_manager = CHAIN_MANAGER
    
    # Migrate existing files on first run
    if not self.chain_manager.base_dir.exists():
        self.chain_manager.migrate_existing_files()
    
    self.chain = []
    
    if os.path.exists(BLOCKCHAIN_DB):
        try:
            self.load_chain()
        except Exception as e:
            print(f"Error loading blockchain: {e}")
            print("Creating new blockchain with genesis block.")
            self.chain = [self.create_genesis_block()]
            self.save_chain()
    else:
        self.chain = [self.create_genesis_block()]
        self.save_chain()

# Update save_chain method:
def save_chain(self):
    """Save blockchain to centralized active directory"""
    if os.path.exists(BLOCKCHAIN_DB):
        self.chain_manager.create_backup(BLOCKCHAIN_DB)
    
    with open(BLOCKCHAIN_DB, "w") as f:
        json.dump(self.to_dict(), f, indent=4)
    
    print(f"💾 [SAVE] Blockchain saved to: {BLOCKCHAIN_DB}")
'''

print("📋 [INTEGRATION GUIDE]")
print("=" * 50)
print("1. Add the ChainDirectoryManager class to your project")
print("2. Update polymorphicblock.py with the integration patch")
print("3. Run the system - it will automatically migrate existing files")
print("4. All new chain files will be organized in system_chains/")
print("=" * 50)