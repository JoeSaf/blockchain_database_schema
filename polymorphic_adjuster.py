import time
import threading
import random
import copy
import json
import os
from pathlib import Path
import glob

class BlockAdjuster:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.timer_thread = None
        self.running = False
        
        # Store original validation method
        self.original_is_chain_valid = self.blockchain.is_chain_valid
        
        # Create a flag to indicate when adjustments are in progress
        self.adjusting = False
        
        # Backup management settings
        self.max_backups = 5  # Maximum number of backups to keep
        
        print("🔧 [ADJUSTER] Block adjuster initialized with backup cleanup")

    def safe_chain_valid(self):
        """A modified chain validation method that doesn't trigger security responses during adjustments"""
        if self.adjusting:
            print("🔧 [ADJUSTER] Validation skipped - adjustment in progress")
            return True
            
        # Use basic validation during adjustments
        for i in range(1, len(self.blockchain.chain)):
            current_block = self.blockchain.chain[i]
            previous_block = self.blockchain.chain[i-1]
            
            if current_block.hash != current_block.calculate_hash():
                print("🔧 [ADJUSTER] Hash mismatch detected but security response suppressed")
                return False
            
            if current_block.previous_hash != previous_block.hash:
                print("🔧 [ADJUSTER] Chain continuity compromised but security response suppressed")
                return False
                
        return True

    def cleanup_old_backups(self):
        """
        Clean up old backup files, keeping only the latest 5 backups
        """
        try:
            # Get the backup directory from chain manager
            if hasattr(self.blockchain, 'chain_manager'):
                backup_dir = self.blockchain.chain_manager.subdirs['backups']
            else:
                backup_dir = Path("system_chains/backups")
            
            if not backup_dir.exists():
                print("🔧 [CLEANUP] Backup directory doesn't exist, nothing to clean")
                return
            
            # Find all backup files matching the backup pattern
            backup_pattern = backup_dir / "backup_blockchain_*.json"
            backup_files = list(backup_dir.glob("backup_blockchain_*.json"))
            
            if len(backup_files) <= self.max_backups:
                print(f"🔧 [CLEANUP] Only {len(backup_files)} backups found, no cleanup needed")
                return
            
            # Sort backup files by modification time (newest first)
            backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            # Keep only the latest max_backups files
            files_to_keep = backup_files[:self.max_backups]
            files_to_delete = backup_files[self.max_backups:]
            
            print(f"🔧 [CLEANUP] Found {len(backup_files)} backup files")
            print(f"🔧 [CLEANUP] Keeping {len(files_to_keep)} latest backups")
            print(f"🔧 [CLEANUP] Deleting {len(files_to_delete)} old backups")
            
            # Delete old backup files
            deleted_count = 0
            for backup_file in files_to_delete:
                try:
                    backup_file.unlink()  # Delete the file
                    print(f"🗑️  [CLEANUP] Deleted: {backup_file.name}")
                    deleted_count += 1
                except Exception as e:
                    print(f"❌ [CLEANUP] Failed to delete {backup_file.name}: {str(e)}")
            
            print(f"✅ [CLEANUP] Successfully cleaned up {deleted_count} old backup files")
            
            # Log the remaining backups
            print(f"📁 [CLEANUP] Remaining backups:")
            for i, backup_file in enumerate(files_to_keep, 1):
                mod_time = time.strftime('%Y-%m-%d %H:%M:%S', 
                                      time.localtime(backup_file.stat().st_mtime))
                size_kb = backup_file.stat().st_size / 1024
                print(f"   {i}. {backup_file.name} ({size_kb:.1f} KB, {mod_time})")
                
        except Exception as e:
            print(f"❌ [CLEANUP] Error during backup cleanup: {str(e)}")

    def cleanup_all_backup_types(self):
        """
        Clean up all types of backup files in the system, not just regular backups
        """
        try:
            if hasattr(self.blockchain, 'chain_manager'):
                backup_dir = self.blockchain.chain_manager.subdirs['backups']
            else:
                backup_dir = Path("system_chains/backups")
            
            if not backup_dir.exists():
                return
            
            # Define patterns for different backup types
            backup_patterns = [
                "backup_blockchain_*.json",      # Regular backups
                "clean_blockchain_db_*.json",    # Clean chain backups
                "*_backup_*.json"                # Any other backup files
            ]
            
            total_cleaned = 0
            
            for pattern in backup_patterns:
                backup_files = list(backup_dir.glob(pattern))
                
                if len(backup_files) <= self.max_backups:
                    continue
                
                # Sort by modification time (newest first)
                backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                
                # Delete old files
                files_to_delete = backup_files[self.max_backups:]
                
                for backup_file in files_to_delete:
                    try:
                        backup_file.unlink()
                        total_cleaned += 1
                        print(f"🗑️  [CLEANUP] Deleted: {backup_file.name}")
                    except Exception as e:
                        print(f"❌ [CLEANUP] Failed to delete {backup_file.name}: {str(e)}")
            
            if total_cleaned > 0:
                print(f"✅ [CLEANUP] Total files cleaned: {total_cleaned}")
            else:
                print("🔧 [CLEANUP] No cleanup needed for any backup types")
                
        except Exception as e:
            print(f"❌ [CLEANUP] Error during comprehensive backup cleanup: {str(e)}")

    def safely_reorder_blocks(self, start_index=1, count=9):
        """
        Safely reorders a section of blocks while maintaining blockchain integrity.
        Now includes automatic backup cleanup after reordering.
        """
        if len(self.blockchain.chain) < (start_index + count):
            available_count = len(self.blockchain.chain) - start_index
            if available_count <= 1:
                print(f"🔧 [ADJUSTER] Not enough blocks for reordering (need at least 2, have {available_count})")
                return False
            count = available_count
            print(f"🔧 [ADJUSTER] Adjusting count to {count} based on available blocks")
        
        print(f"🔧 [ADJUSTER] Starting reorder of blocks {start_index} to {start_index+count-1}...")
        
        # Set adjustment flag and temporarily override validation
        self.adjusting = True
        original_validation = self.blockchain.is_chain_valid
        self.blockchain.is_chain_valid = self.safe_chain_valid
        
        try:
            # Make a deep copy of the chain section we want to reorder
            blocks_to_reorder = copy.deepcopy(self.blockchain.chain[start_index:start_index+count])
            
            # Shuffle the copied blocks
            random.shuffle(blocks_to_reorder)
            
            # Create the new chain: beginning + shuffled + end
            new_chain = copy.deepcopy(self.blockchain.chain[:start_index])
            
            # Reconstruct the hash chain links for the shuffled section
            for i, block in enumerate(blocks_to_reorder):
                if i == 0:
                    # Link the first shuffled block to the last unshuffled block
                    block.previous_hash = new_chain[-1].hash
                else:
                    # Link each subsequent shuffled block to the previous shuffled block
                    block.previous_hash = blocks_to_reorder[i-1].hash
                    
                # Update the block index to match its new position
                block.index = start_index + i
                
                # Recalculate the hash for this block
                block.hash = block.calculate_hash()
                
                # Add to our reconstructed chain
                new_chain.append(block)
            
            # If there are more blocks after our shuffled section
            if start_index + count < len(self.blockchain.chain):
                # Get the final shuffled block's hash
                last_shuffled_hash = new_chain[-1].hash
                
                # Get the remaining blocks and update their links
                remaining_blocks = copy.deepcopy(self.blockchain.chain[start_index+count:])
                
                # Fix the first remaining block's link to the last shuffled block
                remaining_blocks[0].previous_hash = last_shuffled_hash
                remaining_blocks[0].hash = remaining_blocks[0].calculate_hash()
                
                # Fix all subsequent remaining blocks
                for i in range(1, len(remaining_blocks)):
                    remaining_blocks[i].previous_hash = remaining_blocks[i-1].hash
                    remaining_blocks[i].index = start_index + count + i
                    remaining_blocks[i].hash = remaining_blocks[i].calculate_hash()
                
                # Add the remaining blocks to our new chain
                new_chain.extend(remaining_blocks)
            
            # Replace the chain with our reordered version
            self.blockchain.chain = new_chain
            
            # Save the reordered chain (this creates a backup)
            self.blockchain.save_chain()
            
            # Clean up old backups after successful reordering
            print("🔧 [ADJUSTER] Cleaning up old backups...")
            self.cleanup_old_backups()
            
            print(f"🔧 [ADJUSTER] Successfully reordered {count} blocks")
            return True
            
        except Exception as e:
            print(f"🔧 [ADJUSTER] Error during reordering: {e}")
            return False
            
        finally:
            # Always restore original validation and clear adjustment flag
            self.adjusting = False
            self.blockchain.is_chain_valid = original_validation

    def start_timer(self, interval=300):
        """
        Start a background timer to periodically reorder blocks.
        """
        if self.running:
            print("🔧 [ADJUSTER] Timer already running")
            return self.timer_thread
            
        def loop():
            print(f"🔧 [ADJUSTER] Background timer started (interval: {interval} seconds)")
            while self.running:
                try:
                    # Wait for the interval
                    time.sleep(interval)
                    
                    if not self.running:
                        break
                        
                    # Check if we have enough blocks to reorder
                    if len(self.blockchain.chain) > 2:
                        # Calculate how many blocks we can safely reorder
                        max_blocks = min(30, len(self.blockchain.chain) - 1)
                        self.safely_reorder_blocks(start_index=1, count=max_blocks)
                    else:
                        print("🔧 [ADJUSTER] Not enough blocks for reordering (need at least 3)")
                        
                except Exception as e:
                    print(f"🔧 [ADJUSTER] Timer error: {e}")
                    
            print("🔧 [ADJUSTER] Background timer stopped")
                
        # Start the timer in a background thread
        self.running = True
        self.timer_thread = threading.Thread(target=loop, daemon=True)
        self.timer_thread.start()
        
        print(f"🔧 [ADJUSTER] Block reordering timer started (every {interval} seconds)")
        return self.timer_thread
    
    def stop_timer(self):
        """Stop the background timer"""
        self.running = False
        if self.timer_thread:
            print("🔧 [ADJUSTER] Stopping background timer...")
            self.timer_thread.join(timeout=5)
            
    def manual_reorder(self, count=None):
        """Manually trigger a reorder operation"""
        if count is None:
            count = min(20, len(self.blockchain.chain) - 1)
            
        print(f"🔧 [ADJUSTER] Manual reorder triggered")
        return self.safely_reorder_blocks(start_index=1, count=count)

    def manual_cleanup(self):
        """Manually trigger backup cleanup"""
        print("🔧 [ADJUSTER] Manual backup cleanup triggered")
        self.cleanup_all_backup_types()
        
    def get_backup_status(self):
        """Get status information about current backups"""
        try:
            if hasattr(self.blockchain, 'chain_manager'):
                backup_dir = self.blockchain.chain_manager.subdirs['backups']
            else:
                backup_dir = Path("system_chains/backups")
            
            if not backup_dir.exists():
                return {"status": "No backup directory found"}
            
            # Count different types of backup files
            backup_files = list(backup_dir.glob("backup_blockchain_*.json"))
            clean_files = list(backup_dir.glob("clean_blockchain_db_*.json"))
            other_files = list(backup_dir.glob("*_backup_*.json"))
            
            total_size = sum(f.stat().st_size for f in backup_files + clean_files + other_files)
            
            return {
                "status": "Active",
                "backup_directory": str(backup_dir),
                "regular_backups": len(backup_files),
                "clean_backups": len(clean_files),
                "other_backups": len(other_files),
                "total_files": len(backup_files) + len(clean_files) + len(other_files),
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "max_backups_allowed": self.max_backups
            }
            
        except Exception as e:
            return {"status": "Error", "error": str(e)}

    def set_max_backups(self, max_count):
        """Set the maximum number of backups to keep"""
        if max_count < 1:
            print("❌ [ADJUSTER] Maximum backup count must be at least 1")
            return False
            
        old_max = self.max_backups
        self.max_backups = max_count
        print(f"🔧 [ADJUSTER] Maximum backups changed from {old_max} to {max_count}")
        
        # If the new limit is lower, clean up immediately
        if max_count < old_max:
            print("🔧 [ADJUSTER] New limit is lower, cleaning up immediately...")
            self.cleanup_all_backup_types()
            
        return True