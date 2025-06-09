# compatibility_layer.py
"""
Backward Compatibility Integration Layer
Bridges the gap between legacy file paths and new centralized system
"""

import os
import json
import shutil
import time
from pathlib import Path
from centralized_chain_management import ChainDirectoryManager

class CompatibilityManager:
    """
    Manages the transition from legacy file structure to centralized management
    Ensures backward compatibility while enabling new features
    """
    
    def __init__(self):
        self.chain_manager = ChainDirectoryManager()
        self.legacy_files = {
            'blockchain_db.json': 'active',
            'blockStorage.json': 'active', 
            'fallback_db.json': 'fallbacks',
        }
        self.migration_complete = False
        
    def initialize_compatibility_mode(self):
        """
        Initialize the system in compatibility mode
        - Migrate existing files if they exist
        - Create symbolic links for backward compatibility
        - Set up dual-write mode
        """
        print("\n🔄 [COMPATIBILITY] Initializing backward compatibility layer...")
        
        # Step 1: Migrate existing files
        migrated_files = self._migrate_legacy_files()
        
        # Step 2: Create symbolic links for unmigrated systems
        self._create_compatibility_links()
        
        # Step 3: Verify setup
        self._verify_compatibility_setup()
        
        print(f"✅ [COMPATIBILITY] Setup complete. Migrated {migrated_files} files.")
        return migrated_files > 0
    
    def _migrate_legacy_files(self):
        """Migrate existing files to centralized structure"""
        print("📦 [MIGRATION] Moving legacy files to centralized structure...")
        
        migrated_count = 0
        current_dir = Path('.')
        
        for legacy_file, dest_type in self.legacy_files.items():
            legacy_path = current_dir / legacy_file
            
            if legacy_path.exists():
                # Determine destination path
                if dest_type == 'active':
                    dest_path = self.chain_manager.get_path('active', legacy_file)
                else:
                    # For fallback files, add timestamp
                    timestamp = int(legacy_path.stat().st_mtime)
                    dest_path = self.chain_manager.get_path(dest_type, 
                                                          f'legacy_{legacy_file.replace(".json", "")}_{timestamp}.json')
                
                try:
                    # Create backup of legacy file first
                    backup_path = current_dir / f"{legacy_file}.backup"
                    shutil.copy2(str(legacy_path), str(backup_path))
                    
                    # Move to centralized location
                    shutil.move(str(legacy_path), str(dest_path))
                    print(f"  ✅ Migrated: {legacy_file} → {dest_path.relative_to(self.chain_manager.base_dir)}")
                    migrated_count += 1
                    
                except Exception as e:
                    print(f"  ❌ Failed to migrate {legacy_file}: {str(e)}")
                    # Restore from backup if move failed
                    if backup_path.exists():
                        shutil.move(str(backup_path), str(legacy_path))
        
        # Look for pattern-based legacy files
        patterns = [
            'enhanced_fallback_*.json',
            'quarantined_blocks_*.json', 
            'clean_blockchain_*.json',
            'fallback_db_*.json'
        ]
        
        for pattern in patterns:
            for file_path in current_dir.glob(pattern):
                try:
                    # Determine destination based on file name
                    if 'fallback' in file_path.name:
                        dest_path = self.chain_manager.subdirs['fallbacks'] / file_path.name
                    elif 'quarantined' in file_path.name:
                        dest_path = self.chain_manager.subdirs['quarantine'] / file_path.name
                    elif 'clean' in file_path.name:
                        dest_path = self.chain_manager.subdirs['backups'] / file_path.name
                    else:
                        dest_path = self.chain_manager.subdirs['archives'] / file_path.name
                    
                    shutil.move(str(file_path), str(dest_path))
                    print(f"  ✅ Archived: {file_path.name} → {dest_path.relative_to(self.chain_manager.base_dir)}")
                    migrated_count += 1
                    
                except Exception as e:
                    print(f"  ❌ Failed to archive {file_path.name}: {str(e)}")
        
        return migrated_count
    
    def _create_compatibility_links(self):
        """Create symbolic links for backward compatibility"""
        print("🔗 [LINKS] Creating compatibility symbolic links...")
        
        for legacy_file in self.legacy_files.keys():
            legacy_path = Path(legacy_file)
            centralized_path = self.chain_manager.get_path('active', legacy_file)
            
            # Only create link if centralized file exists and legacy doesn't
            if centralized_path.exists() and not legacy_path.exists():
                try:
                    # Create relative symbolic link
                    relative_path = os.path.relpath(str(centralized_path), str(legacy_path.parent))
                    legacy_path.symlink_to(relative_path)
                    print(f"  🔗 Created link: {legacy_file} → {relative_path}")
                    
                except Exception as e:
                    print(f"  ❌ Failed to create link for {legacy_file}: {str(e)}")
                    # If symlink fails, create a compatibility wrapper
                    self._create_compatibility_wrapper(legacy_file, centralized_path)
    
    def _create_compatibility_wrapper(self, legacy_file, centralized_path):
        """Create a Python-based compatibility wrapper if symlinks fail"""
        wrapper_content = f'''# Compatibility wrapper for {legacy_file}
# This file redirects operations to the centralized location
# Generated automatically by CompatibilityManager

import json
import os
from pathlib import Path

CENTRALIZED_PATH = r"{centralized_path}"

def load_data():
    """Load data from centralized location"""
    with open(CENTRALIZED_PATH, 'r') as f:
        return json.load(f)

def save_data(data):
    """Save data to centralized location"""
    with open(CENTRALIZED_PATH, 'w') as f:
        json.dump(data, f, indent=4)

# For direct file reading compatibility
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "get_path":
        print(CENTRALIZED_PATH)
    else:
        data = load_data()
        print(json.dumps(data, indent=2))
'''
        
        wrapper_file = f"{legacy_file}.wrapper.py"
        with open(wrapper_file, 'w') as f:
            f.write(wrapper_content)
        print(f"  📝 Created wrapper: {wrapper_file}")
    
    def _verify_compatibility_setup(self):
        """Verify that compatibility setup is working correctly"""
        print("🔍 [VERIFY] Checking compatibility setup...")
        
        issues = []
        
        # Check that centralized files exist
        active_blockchain = self.chain_manager.get_path('active', 'blockchain_db.json')
        if not active_blockchain.exists():
            issues.append("Main blockchain file not found in centralized location")
        
        # Check that legacy access still works
        for legacy_file in self.legacy_files.keys():
            legacy_path = Path(legacy_file)
            wrapper_path = Path(f"{legacy_file}.wrapper.py")
            
            if not legacy_path.exists() and not wrapper_path.exists():
                issues.append(f"No backward compatibility for {legacy_file}")
        
        if issues:
            print("  ⚠️  Compatibility issues found:")
            for issue in issues:
                print(f"     - {issue}")
        else:
            print("  ✅ All compatibility checks passed")
        
        return len(issues) == 0
    
    def get_file_path(self, filename, file_type='active'):
        """
        Get the correct file path for both legacy and new systems
        
        Args:
            filename: Name of the file
            file_type: Type of file ('active', 'fallback', 'quarantine', etc.)
        
        Returns:
            Path object for the file
        """
        # Always return centralized path
        return self.chain_manager.get_path(file_type, filename)
    
    def dual_write(self, filename, data, file_type='active'):
        """
        Write data to both legacy and centralized locations during transition
        
        Args:
            filename: Name of the file
            data: Data to write
            file_type: Type of file
        """
        # Write to centralized location
        centralized_path = self.chain_manager.get_path(file_type, filename)
        with open(centralized_path, 'w') as f:
            json.dump(data, f, indent=4)
        
        # Also write to legacy location if it exists or is expected
        if filename in self.legacy_files and not self.migration_complete:
            legacy_path = Path(filename)
            try:
                with open(legacy_path, 'w') as f:
                    json.dump(data, f, indent=4)
                print(f"📝 [DUAL-WRITE] Saved to both locations: {filename}")
            except Exception as e:
                print(f"⚠️  [DUAL-WRITE] Failed to write legacy file {filename}: {str(e)}")
    
    def dual_read(self, filename, file_type='active'):
        """
        Read data from centralized location first, fall back to legacy
        
        Args:
            filename: Name of the file
            file_type: Type of file
        
        Returns:
            Loaded data
        """
        # Try centralized location first
        centralized_path = self.chain_manager.get_path(file_type, filename)
        if centralized_path.exists():
            with open(centralized_path, 'r') as f:
                return json.load(f)
        
        # Fall back to legacy location
        legacy_path = Path(filename)
        if legacy_path.exists():
            print(f"📖 [FALLBACK] Reading from legacy location: {filename}")
            with open(legacy_path, 'r') as f:
                return json.load(f)
        
        raise FileNotFoundError(f"File not found in centralized or legacy locations: {filename}")
    
    def cleanup_legacy_files(self):
        """
        Clean up legacy files after migration is complete
        Only call this after verifying everything works with centralized system
        """
        print("🧹 [CLEANUP] Removing legacy files and links...")
        
        for legacy_file in self.legacy_files.keys():
            # Remove symlinks
            legacy_path = Path(legacy_file)
            if legacy_path.is_symlink():
                legacy_path.unlink()
                print(f"  🗑️  Removed symlink: {legacy_file}")
            
            # Remove wrapper files
            wrapper_path = Path(f"{legacy_file}.wrapper.py")
            if wrapper_path.exists():
                wrapper_path.unlink()
                print(f"  🗑️  Removed wrapper: {wrapper_path.name}")
            
            # Remove backup files
            backup_path = Path(f"{legacy_file}.backup")
            if backup_path.exists():
                backup_path.unlink()
                print(f"  🗑️  Removed backup: {backup_path.name}")
        
        self.migration_complete = True
        print("✅ [CLEANUP] Legacy cleanup completed")

# Global compatibility manager instance
compatibility_manager = CompatibilityManager()

def get_blockchain_path():
    """Get the correct blockchain database path for current system"""
    return str(compatibility_manager.get_file_path('blockchain_db.json', 'active'))

def get_block_storage_path():
    """Get the correct block storage path for current system"""
    return str(compatibility_manager.get_file_path('blockStorage.json', 'active'))

def initialize_compatibility():
    """Initialize the compatibility layer - call this before any blockchain operations"""
    return compatibility_manager.initialize_compatibility_mode()

# Backward compatible constants that modules can import
BLOCKCHAIN_DB = get_blockchain_path()
BLOCKSTOR = get_block_storage_path()
