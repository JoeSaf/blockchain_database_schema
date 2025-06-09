import json
import os

class BlockchainStorage:
    def __init__(self, filename="blockchain_data.json"):
        self.filename = filename

    def save_blockchain(self, blockchain):
        """Saves the blockchain data to a file."""
        with open(self.filename, "w") as f:
            json.dump(blockchain.to_dict(), f, indent=4)

    def load_blockchain(self, blockchain_class, block_class):
        """Loads blockchain data from a file and reconstructs the chain."""
        if not os.path.exists(self.filename):
            return blockchain_class()  # Return a new blockchain if file doesn't exist

        with open(self.filename, "r") as f:
            data = json.load(f)
        
        blockchain = blockchain_class()
        blockchain.chain = [
            block_class(
                block["index"], block["timestamp"], block["data"], block["previous_hash"]
            ) for block in data
        ]

        return blockchain
