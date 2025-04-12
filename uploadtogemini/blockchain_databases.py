import json
import os
import hashlib
import time
import base64
import random
import subprocess
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# File paths for database storage
BLOCKSTOR = "blockStorage.json"
BLOCKCHAIN_DB = "blockchain_db.json"

class DatabaseBlock:
    def __init__(self, index, timestamp, data, storpath, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.storpath = storpath
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
        
    def calculate_hash(self):
        block_string = json.dumps({"index": self.index, "timestamp": self.timestamp,
                                   "data": self.data, "previous_hash": self.previous_hash,
                                   "storpath": self.storpath},
                                  sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
    
    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "storpath": self.storpath,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }
        
class DatabaseStorage:
    """Blockchain-based database storage system"""
    
    def __init__(self):
        if os.path.exists(BLOCKSTOR):
            self.load_chain()
        else:
            self.chain = [self.create_genesis_block()]
            self.save_chain()
        
    def create_genesis_block(self):
        return DatabaseBlock(0, time.time(), {"action": "genesis", "message": "Genesis Database Block"}, "", "0")
    
    def get_latest_block(self):
        return self.chain[-1]
    
    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.hash = new_block.calculate_hash()
        self.chain.append(new_block)
        self.save_chain()
        
    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            if current_block.hash != current_block.calculate_hash():
                self._trigger_alert("Hash mismatch detected in database storage")
                return False
            
            if current_block.previous_hash != previous_block.hash:
                self._trigger_alert("Chain continuity compromised in database storage")
                return False
            
        return True
    
    def _trigger_alert(self, message):
        print(f"WARNING: {message}")
        # You could integrate with the polymorphic security system here
        
    def to_dict(self):
        return [block.to_dict() for block in self.chain]
    
    def save_chain(self):
        """Saves the chain into the json based db"""
        with open(BLOCKSTOR, "w") as f:
            json.dump(self.to_dict(), f, indent=4)
            
    def load_chain(self):
        """Loads the chain from file"""
        with open(BLOCKSTOR, "r") as f:
            chain_data = json.load(f)
            self.chain = []
            for block_data in chain_data:
                block = DatabaseBlock(
                    block_data["index"],
                    block_data["timestamp"],
                    block_data["data"],
                    block_data["storpath"],
                    block_data["previous_hash"]
                )
                block.hash = block_data["hash"]
                self.chain.append(block)
    
    def create_database(self, name, schema, owner):
        """Create a new database with the given schema"""
        # Create a directory for the database
        db_path = os.path.join("databases", name)
        if not os.path.exists(db_path):
            os.makedirs(db_path, exist_ok=True)
            
        # Write schema to file
        schema_file = os.path.join(db_path, "schema.json")
        with open(schema_file, "w") as f:
            json.dump(schema, f, indent=4)
            
        # Add block to blockchain
        block_data = {
            "action": "create_database",
            "name": name,
            "owner": owner,
            "timestamp": time.time()
        }
        
        new_block = DatabaseBlock(
            index=len(self.chain),
            timestamp=time.time(),
            data=block_data,
            storpath=db_path,
            previous_hash="" 
        )
        
        self.add_block(new_block)
        return db_path
    
    def list_databases(self):
        """List all databases in the blockchain"""
        databases = []
        for block in self.chain:
            if block.data.get("action") == "create_database":
                db_name = block.data.get("name")
                owner = block.data.get("owner")
                timestamp = block.timestamp
                databases.append({
                    "name": db_name,
                    "owner": owner,
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)),
                    "path": block.storpath
                })
        
        return databases
    
    def store_item(self, db_name, item_name, item_data, owner):
        """Store an item in a specific database"""
        # Find the database path
        db_path = None
        for block in self.chain:
            if block.data.get("action") == "create_database" and block.data.get("name") == db_name:
                db_path = block.storpath
                break
                
        if not db_path:
            print(f"Database '{db_name}' not found!")
            return None
        
        # Create an item file
        timestamp = int(time.time())
        item_filename = f"{item_name}_{timestamp}.json"
        item_path = os.path.join(db_path, item_filename)
        
        # Store the item data
        with open(item_path, "w") as f:
            if isinstance(item_data, dict) or isinstance(item_data, list):
                json.dump(item_data, f, indent=4)
            else:
                f.write(str(item_data))
        
        # Add block to blockchain
        block_data = {
            "action": "store_item",
            "database": db_name,
            "item_name": item_name,
            "owner": owner,
            "timestamp": time.time()
        }
        
        new_block = DatabaseBlock(
            index=len(self.chain),
            timestamp=time.time(),
            data=block_data,
            storpath=item_path,
            previous_hash=""  
        )
        
        self.add_block(new_block)
        return item_path
    
    def get_database_items(self, db_name):
        """Get all items in a specific database"""
        items = []
        for block in self.chain:
            if block.data.get("action") == "store_item" and block.data.get("database") == db_name:
                item_name = block.data.get("item_name")
                owner = block.data.get("owner")
                timestamp = block.timestamp
                items.append({
                    "name": item_name,
                    "owner": owner,
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)),
                    "path": block.storpath
                })
        
        return items


class DatabaseManager:
    """Interface for managing blockchain databases"""
    
    def __init__(self, auth_system):
        self.db_storage = DatabaseStorage()
        self.auth_system = auth_system
        
        # Ensure databases directory exists
        if not os.path.exists("databases"):
            os.makedirs("databases")
    
    def create_database(self, name, schema, username):
        """Create a new database with the given schema"""
        # Verify admin privileges through the auth system
        if self.auth_system.users.get(username, {}).get("role") != "admin":
            print("Only admin users can create databases!")
            return None
            
        return self.db_storage.create_database(name, schema, username)
    
    def list_databases(self, username=None, role=None):
        """List databases (filter by username if provided)"""
        all_dbs = self.db_storage.list_databases()
        
        # Handle case where auth_system might not be fully initialized
        if not hasattr(self.auth_system, 'users'):
            return all_dbs
            
        # If username is provided, filter by owner
        if username and role != "admin":
            return [db for db in all_dbs if db["owner"] == username]
        
        # Admin can see all databases
        return all_dbs
    
    def store_item(self, db_name, item_name, item_data, username):
        """Store an item in a database"""
        # Check if database exists and user has permission
        all_dbs = self.db_storage.list_databases()
        db = next((d for d in all_dbs if d["name"] == db_name), None)
        
        if not db:
            print(f"Database '{db_name}' not found!")
            return None
        
        # Check if user is owner or admin
        user_role = self.auth_system.users.get(username, {}).get("role")
        if db["owner"] != username and user_role != "admin":
            print(f"You don't have permission to modify this database!")
            return None
        
        return self.db_storage.store_item(db_name, item_name, item_data, username)
    
    def get_database_items(self, db_name, username=None, role=None):
        """Get items from a database (filter by access permissions)"""
        # Check if database exists
        all_dbs = self.db_storage.list_databases()
        db = next((d for d in all_dbs if d["name"] == db_name), None)
        
        if not db:
            print(f"Database '{db_name}' not found!")
            return []
        
        # Check if user has permission to view
        if username and role != "admin" and db["owner"] != username:
            print(f"You don't have permission to view this database!")
            return []
        
        return self.db_storage.get_database_items(db_name)

# Initialize database folder
def initialize_database_folders():
    """Initialize the database storage directories"""
    # Create main databases directory
    database_path = "databases"
    if not os.path.exists(database_path):
        os.makedirs(database_path)
        print(f"Created database directory at {os.path.abspath(database_path)}")
    else:
        print(f"Database directory already exists at {os.path.abspath(database_path)}")
    
    # Create user data directory
    userData_path = "userData"
    if not os.path.exists(userData_path):
        os.makedirs(userData_path)
        print(f"Created userData directory at {os.path.abspath(userData_path)}")
    
    return database_path