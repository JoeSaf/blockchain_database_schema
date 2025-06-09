class CoreRefresher:
    def __init__(self, blockchain, db_manager, storage):
        self.blockchain = blockchain
        self.db_manager = db_manager
        self.storage = storage

    def refresh(self):
        print("[CoreRefresher] Refreshing blockchain and database state...")
        # Optionally regenerate hashes or verify integrity
        if hasattr(self.blockchain, "rehash_chain"):
            self.blockchain.rehash_chain()

        # Save latest state to file
        self.storage.save_blockchain(self.blockchain)

        # Optionally call a sync or verify method for DB
        if hasattr(self.db_manager, "sync"):
            self.db_manager.sync()
