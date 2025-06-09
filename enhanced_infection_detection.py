import json
import os
import time
import hashlib

class EnhancedBlockchain:
    def __init__(self):
        self.chain = []
        self.infected_blocks = []
        
        if os.path.exists("blockchain_db.json"):
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
    
    def identify_infected_blocks(self):
        """
        Enhanced method to identify all infected blocks and return their details
        Returns a list of infected block information
        """
        infected_blocks = []
        
        print("\n🔍 [INFECTION SCANNER] Starting comprehensive blockchain scan...")
        print("=" * 60)
        
        for i in range(1, len(self.chain)):  # Skip genesis block
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # Check 1: Hash Integrity
            calculated_hash = current_block.calculate_hash()
            if current_block.hash != calculated_hash:
                infection_info = {
                    "block_id": current_block.index,
                    "infection_type": "HASH_MISMATCH",
                    "stored_hash": current_block.hash,
                    "calculated_hash": calculated_hash,
                    "block_data": current_block.data,
                    "timestamp": current_block.timestamp,
                    "severity": "CRITICAL"
                }
                infected_blocks.append(infection_info)
                print(f"🚨 [CRITICAL] Block #{current_block.index} - HASH MISMATCH DETECTED")
                print(f"   Stored Hash:    {current_block.hash[:16]}...")
                print(f"   Calculated Hash: {calculated_hash[:16]}...")
            
            # Check 2: Chain Continuity
            if current_block.previous_hash != previous_block.hash:
                infection_info = {
                    "block_id": current_block.index,
                    "infection_type": "CHAIN_BREAK",
                    "expected_previous": previous_block.hash,
                    "actual_previous": current_block.previous_hash,
                    "block_data": current_block.data,
                    "timestamp": current_block.timestamp,
                    "severity": "CRITICAL"
                }
                infected_blocks.append(infection_info)
                print(f"🚨 [CRITICAL] Block #{current_block.index} - CHAIN CONTINUITY BROKEN")
                print(f"   Expected Previous: {previous_block.hash[:16]}...")
                print(f"   Actual Previous:   {current_block.previous_hash[:16]}...")
            
            # Check 3: Timestamp Validation (blocks shouldn't go backwards in time)
            if i > 0 and current_block.timestamp < previous_block.timestamp:
                infection_info = {
                    "block_id": current_block.index,
                    "infection_type": "TIMESTAMP_ANOMALY",
                    "current_timestamp": current_block.timestamp,
                    "previous_timestamp": previous_block.timestamp,
                    "block_data": current_block.data,
                    "severity": "WARNING"
                }
                infected_blocks.append(infection_info)
                print(f"⚠️  [WARNING] Block #{current_block.index} - TIMESTAMP ANOMALY")
                print(f"   Block timestamp is earlier than previous block")
            
            # Check 4: Data Integrity (basic checks)
            if not isinstance(current_block.data, dict):
                infection_info = {
                    "block_id": current_block.index,
                    "infection_type": "DATA_CORRUPTION",
                    "issue": "Data is not a valid dictionary",
                    "block_data": current_block.data,
                    "timestamp": current_block.timestamp,
                    "severity": "HIGH"
                }
                infected_blocks.append(infection_info)
                print(f"🔥 [HIGH] Block #{current_block.index} - DATA CORRUPTION")
        
        print("=" * 60)
        print(f"🔍 [SCAN COMPLETE] Found {len(infected_blocks)} infected blocks")
        
        return infected_blocks
    
    def create_clean_fallback_chain(self, infected_blocks):
        """
        Create a clean fallback chain excluding infected blocks
        """
        if not infected_blocks:
            print("✅ No infected blocks found. Chain is clean.")
            return False
        
        print("\n🛡️  [QUARANTINE] Creating clean fallback chain...")
        print("=" * 60)
        
        # Get list of infected block IDs
        infected_ids = [block_info["block_id"] for block_info in infected_blocks]
        
        print(f"🚫 Quarantining blocks: {infected_ids}")
        
        # Create clean chain excluding infected blocks
        clean_blocks = []
        
        # Always include genesis block (index 0)
        clean_blocks.append(self.chain[0])
        
        # Add non-infected blocks
        for block in self.chain[1:]:
            if block.index not in infected_ids:
                clean_blocks.append(block)
                print(f"✅ Block #{block.index} - CLEAN (preserved)")
            else:
                print(f"🚫 Block #{block.index} - INFECTED (quarantined)")
        
        # Rebuild hash chain for clean blocks
        print("\n🔧 [REBUILD] Reconstructing hash chain...")
        for i in range(1, len(clean_blocks)):
            # Update index to reflect new position
            clean_blocks[i].index = i
            # Link to previous clean block
            clean_blocks[i].previous_hash = clean_blocks[i-1].hash
            # Recalculate hash
            clean_blocks[i].hash = clean_blocks[i].calculate_hash()
            print(f"🔗 Block #{i} - Hash chain rebuilt")
        
        # Save fallback data
        fallback_data = {
            "created_at": time.time(),
            "breach_reason": "Automated infection detection and quarantine",
            "infected_blocks_quarantined": len(infected_blocks),
            "infected_block_details": infected_blocks,
            "clean_chain": [block.to_dict() for block in clean_blocks],
            "original_chain_length": len(self.chain),
            "clean_chain_length": len(clean_blocks),
            "users": self.extract_users_from_clean_chain(clean_blocks)
        }
        
        # Save to fallback file
        fallback_filename = f"fallback_db_{int(time.time())}.json"
        with open(fallback_filename, "w") as f:
            json.dump(fallback_data, f, indent=4)
        
        # Save infected blocks separately for forensic analysis
        infected_filename = f"infected_blocks_{int(time.time())}.json"
        with open(infected_filename, "w") as f:
            json.dump({
                "quarantine_timestamp": time.time(),
                "infected_blocks": infected_blocks,
                "forensic_data": [block.to_dict() for block in self.chain if block.index in infected_ids]
            }, f, indent=4)
        
        print("=" * 60)
        print(f"✅ [SUCCESS] Fallback chain created: {fallback_filename}")
        print(f"🔍 [FORENSICS] Infected blocks saved: {infected_filename}")
        print(f"📊 Original chain: {len(self.chain)} blocks")
        print(f"📊 Clean chain: {len(clean_blocks)} blocks")
        print(f"📊 Quarantined: {len(infected_blocks)} blocks")
        
        # Replace current chain with clean chain
        self.chain = clean_blocks
        self.save_chain()
        
        return True
    
    def extract_users_from_clean_chain(self, clean_chain):
        """Extract user data from clean chain blocks"""
        users = {}
        for block in clean_chain:
            if block.data.get("action") == "register":
                username = block.data.get("username")
                role = block.data.get("role", "user")
                public_key = block.data.get("public_key")
                private_key = block.data.get("private_key")
                
                if username:
                    users[username] = {
                        "role": role,
                        "public_key": public_key,
                        "private_key": private_key,
                        "migrated_at": time.time(),
                        "source_block": block.index
                    }
        return users
    
    def enhanced_infection_scan_and_clean(self):
        """
        Main method to perform comprehensive infection detection and cleanup
        """
        print("\n" + "🔒" * 20 + " BLOCKCHAIN SECURITY SCAN " + "🔒" * 20)
        
        # Step 1: Identify infected blocks
        infected_blocks = self.identify_infected_blocks()
        
        if not infected_blocks:
            print("\n✅ [ALL CLEAR] Blockchain is clean and secure!")
            return True
        
        # Step 2: Display infection summary
        print(f"\n📋 [INFECTION SUMMARY]")
        print("=" * 60)
        
        for infection in infected_blocks:
            print(f"Block ID: #{infection['block_id']}")
            print(f"  Type: {infection['infection_type']}")
            print(f"  Severity: {infection['severity']}")
            if 'block_data' in infection:
                action = infection['block_data'].get('action', 'unknown')
                print(f"  Action: {action}")
            print(f"  Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(infection['timestamp']))}")
            print("-" * 40)
        
        # Step 3: Create clean fallback chain
        success = self.create_clean_fallback_chain(infected_blocks)
        
        if success:
            print("\n🎉 [RECOVERY COMPLETE] System has been sanitized and secured!")
            print("🔍 Forensic data has been preserved for analysis.")
            print("✅ Clean blockchain is now active.")
        
        return success
    
    def calculate_hash(self):
        """Calculate hash for a block"""
        block_string = json.dumps({
            "index": self.index, 
            "timestamp": self.timestamp, 
            "data": self.data, 
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
    
    def save_chain(self):
        """Save blockchain to file"""
        with open("blockchain_db.json", "w") as f:
            json.dump([block.to_dict() for block in self.chain], f, indent=4)
    
    def load_chain(self):
        """Load blockchain from file"""
        # This would need to be implemented based on your Block class
        pass

# Integration with existing polymorphicblock.py
class EnhancedBlockchainMixin:
    """
    Mixin to add enhanced infection detection to existing Blockchain class
    """
    
    def is_chain_valid(self):
        """
        Enhanced chain validation that identifies and quarantines infected blocks
        """
        print("\n🔍 [SECURITY] Running enhanced blockchain validation...")
        
        # Use the enhanced detection system
        infected_blocks = self.identify_infected_blocks()
        
        if infected_blocks:
            print(f"\n🚨 [ALERT] {len(infected_blocks)} infected blocks detected!")
            
            # Echo infected block IDs
            infected_ids = [block["block_id"] for block in infected_blocks]
            print(f"🚫 Infected Block IDs: {infected_ids}")
            
            # Create clean fallback
            self.create_clean_fallback_chain(infected_blocks)
            
            return False
        
        print("✅ [SECURE] Blockchain validation passed!")
        return True
    
    def identify_infected_blocks(self):
        """Same as EnhancedBlockchain.identify_infected_blocks"""
        infected_blocks = []
        
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # Hash integrity check
            if current_block.hash != current_block.calculate_hash():
                infected_blocks.append({
                    "block_id": current_block.index,
                    "infection_type": "HASH_MISMATCH",
                    "stored_hash": current_block.hash,
                    "calculated_hash": current_block.calculate_hash(),
                    "block_data": current_block.data,
                    "timestamp": current_block.timestamp,
                    "severity": "CRITICAL"
                })
                print(f"🚨 INFECTED BLOCK DETECTED: #{current_block.index} (Hash Mismatch)")
            
            # Chain continuity check
            if current_block.previous_hash != previous_block.hash:
                infected_blocks.append({
                    "block_id": current_block.index,
                    "infection_type": "CHAIN_BREAK",
                    "expected_previous": previous_block.hash,
                    "actual_previous": current_block.previous_hash,
                    "block_data": current_block.data,
                    "timestamp": current_block.timestamp,
                    "severity": "CRITICAL"
                })
                print(f"🚨 INFECTED BLOCK DETECTED: #{current_block.index} (Chain Break)")
        
        return infected_blocks
    
    def create_clean_fallback_chain(self, infected_blocks):
        """Same as EnhancedBlockchain.create_clean_fallback_chain"""
        if not infected_blocks:
            return False
        
        infected_ids = [block_info["block_id"] for block_info in infected_blocks]
        print(f"\n🚫 QUARANTINING INFECTED BLOCKS: {infected_ids}")
        
        # Create clean chain
        clean_blocks = [self.chain[0]]  # Always keep genesis
        
        for block in self.chain[1:]:
            if block.index not in infected_ids:
                clean_blocks.append(block)
                print(f"✅ Block #{block.index} preserved (clean)")
            else:
                print(f"🚫 Block #{block.index} quarantined (infected)")
        
        # Rebuild hash chain
        for i in range(1, len(clean_blocks)):
            clean_blocks[i].index = i
            clean_blocks[i].previous_hash = clean_blocks[i-1].hash
            clean_blocks[i].hash = clean_blocks[i].calculate_hash()
        
        # Save fallback
        fallback_data = {
            "created_at": time.time(),
            "breach_reason": "Enhanced infection detection and quarantine",
            "infected_blocks_quarantined": infected_ids,
            "infected_block_details": infected_blocks,
            "clean_chain": [block.to_dict() for block in clean_blocks],
            "users": self._extract_users_from_blocks(clean_blocks)
        }
        
        fallback_filename = f"enhanced_fallback_{int(time.time())}.json"
        with open(fallback_filename, "w") as f:
            json.dump(fallback_data, f, indent=4)
        
        print(f"✅ FALLBACK CREATED: {fallback_filename}")
        print(f"📊 Clean chain: {len(clean_blocks)} blocks (removed {len(infected_ids)} infected)")
        
        # Replace chain with clean version
        self.chain = clean_blocks
        self.save_chain()
        
        return True
    
    def _extract_users_from_blocks(self, blocks):
        """Extract user data from blocks"""
        users = {}
        for block in blocks:
            if block.data.get("action") == "register":
                username = block.data.get("username")
                if username:
                    users[username] = {
                        "role": block.data.get("role", "user"),
                        "public_key": block.data.get("public_key"),
                        "private_key": block.data.get("private_key"),
                        "migrated_at": time.time()
                    }
        return users

# Usage example:
"""
# To integrate with your existing system, modify polymorphicblock.py:

class Blockchain(EnhancedBlockchainMixin):
    # ... your existing Blockchain class code ...
    pass

# Or use directly:
enhanced_blockchain = EnhancedBlockchain()
enhanced_blockchain.enhanced_infection_scan_and_clean()
"""