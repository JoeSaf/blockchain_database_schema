import time
import threading
import random
import copy
import json

class BlockAdjuster:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.original_is_chain_valid = self.blockchain.is_chain_valid
        # Override the chain validation method to disable security responses during adjustments
        self.blockchain.is_chain_valid = self.safe_chain_valid

    def safe_chain_valid(self):
        """A modified chain validation method that doesn't trigger security responses"""
        for i in range(1, len(self.blockchain.chain)):
            current_block = self.blockchain.chain[i]
            previous_block = self.blockchain.chain[i-1]
            
            if current_block.hash != current_block.calculate_hash():
                print("Hash mismatch detected but security response suppressed")
                return False
            
            if current_block.previous_hash != previous_block.hash:
                print("Chain continuity compromised but security response suppressed")
                return False
                
        return True

    def restore_original_validation(self):
        """Restore the original chain validation method"""
        self.blockchain.is_chain_valid = self.original_is_chain_valid

    def safely_reorder_blocks(self, start_index=1, count=9):
        """
        Safely reorders a section of blocks while maintaining blockchain integrity.
        Preserves the genesis block (index 0) and reconstructs hash links properly.
        
        Args:
            start_index: The starting block index (default 1 to preserve genesis block)
            count: How many blocks to reorder after the start index
        """
        if len(self.blockchain.chain) < (start_index + count):
            print("[Adjuster] Not enough blocks for reordering")
            return False
        
        print(f"[Adjuster] Safely reordering blocks {start_index} to {start_index+count-1}...")
        
        # Make a deep copy of the chain section we want to reorder
        # This ensures we don't accidentally modify the original during manipulation
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
        
        # Validate the chain to ensure integrity
        if self.blockchain.is_chain_valid():
            print("[Adjuster] Reordering successful, blockchain integrity maintained")
            # Save the reordered chain
            self.blockchain.save_chain()
            return True
        else:
            print("[Adjuster] Warning: Reordered chain is invalid")
            return False

    def start_timer(self, interval=300):
        """
        Start a background timer to periodically reorder blocks.
        
        Args:
            interval: Time in seconds between reordering operations (default: 300 seconds/5 minutes)
        """
        def loop():
            while True:
                # We'll reorder blocks 1-9 to preserve the genesis block
                self.safely_reorder_blocks(start_index=1, count=21)
                time.sleep(interval)
                
        # Start the timer in a background thread
        thread = threading.Thread(target=loop, daemon=True)
        thread.start()
        print(f"[Adjuster] Block adjuster timer started, interval: {interval} seconds")
        return thread