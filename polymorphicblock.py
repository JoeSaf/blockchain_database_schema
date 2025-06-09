import json
import os
import getpass
import hashlib
import time
import base64
import random
import subprocess
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import blockchain_databases
from polymorphic_adjuster import BlockAdjuster
import shutil

# File to store blockchain data
BLOCKCHAIN_DB = "blockchain_db.json"
# Visible security script location
# SECURITY_SCRIPT = "blockchain_security.py"

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
        
    def calculate_hash(self):
        block_string = json.dumps({"index": self.index, "timestamp": self.timestamp, 
                                  "data": self.data, "previous_hash": self.previous_hash}, 
                                  sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
    
    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

class Blockchain:
    def __init__(self):
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
        
    def create_genesis_block(self):
        return Block(0, time.time(), {"action": "genesis", "message": "Genesis Block"}, "0")
    
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
                # Blockchain integrity compromised, trigger fallback response
                self._trigger_fallback_response("Hash mismatch detected")
                return False
            
            if current_block.previous_hash != previous_block.hash:
                # Blockchain integrity compromised, trigger fallback response
                self._trigger_fallback_response("Chain continuity broken")
                return False
                
        return True
    
    def _trigger_fallback_response(self, breach_reason):
        """Creates a fallback database when blockchain integrity is compromised"""
        print(f"WARNING: Blockchain integrity compromised - {breach_reason}")
        print("Initiating security response...")

        fallback_db = "fallback_db.json"
        fallback_data = {
            "created_at": time.time(),
            "breach_reason": breach_reason,
            "users": {}
        }

        for block in self.chain:
            if block.data.get("action") == "register":
                username = block.data.get("username")
                role = block.data.get("role")
                private_key = block.data.get("private_key")
                public_key = block.data.get("public_key")

                if username:
                    fallback_data["users"][username] = {
                        "role": role,
                        "private_key": private_key,
                        "public_key": public_key,
                        "migrated_at": time.time()
                    }

        with open(fallback_db, "w") as f:
            json.dump(fallback_data, f, indent=4)

        print("\nSecurity measures completed:")
        print(f"- Created fallback database: {fallback_db}")
        print(f"- Migrated {len(fallback_data['users'])} users to fallback database")
        print("- System will now use the fallback database")

        self.rehash_chain()
        print("- Blockchain rehashed to restore integrity")
    
    def rehash_chain(self):
        """Recalculate all hashes to ensure chain integrity"""
        if len(self.chain) < 20:  # Replace with your known minimum if needed
            print("WARNING: Chain size seems unexpectedly low. Aborting rehash to prevent data loss.")
            return

        for i in range(1, len(self.chain)):
            self.chain[i].previous_hash = self.chain[i-1].hash
            self.chain[i].hash = self.chain[i].calculate_hash()

        print("Chain rehashed successfully")
        self.save_chain()
    
    def to_dict(self):
        return [block.to_dict() for block in self.chain]
    
    def save_chain(self):
        """Save blockchain to file"""
        with open(BLOCKCHAIN_DB, "w") as f:
            json.dump(self.to_dict(), f, indent=4)
    
    def load_chain(self):
        """Load blockchain from file"""
        with open(BLOCKCHAIN_DB, "r") as f:
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

class User:
    def __init__(self, username, role, private_key=None):
        self.username = username
        self.role = role
        
        if private_key:
            self.private_key = private_key
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
        self.public_key = self.private_key.public_key()
        
        # Initialize user folder when creating a user
        self.initialize_user_folder()
    
    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def get_private_key_pem(self, password=None):
        """Serialize private key to PEM format"""
        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
            
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        ).decode('utf-8')
    
    def sign_message(self, message):
        message_bytes = message.encode('utf-8')
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    def initialize_user_folder(self):
        """Initialize user's personal folder in userData directory"""
        user_folder = os.path.join("userData", self.username)
        
        # Create user folder if it doesn't exist
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)
            print(f"Created user folder for {self.username}")
            
        # Create a user info file to store metadata
        user_info = {
            "username": self.username,
            "role": self.role,
            "created_at": time.time(),
            "public_key": self.get_public_key_pem()
        }
        
        # Save user info to the user folder
        with open(os.path.join(user_folder, "user_info.json"), "w") as f:
            json.dump(user_info, f, indent=4)
            
        return user_folder
        
    def store_user_item(self, item_name, item_data):
        """Store item data in the user's personal folder"""
        user_folder = os.path.join("userData", self.username)
        
        # Ensure user folder exists
        if not os.path.exists(user_folder):
            self.initialize_user_folder()
            
        # Create a unique filename for the item
        timestamp = int(time.time())
        item_filename = f"{item_name}_{timestamp}.json"
        item_path = os.path.join(user_folder, item_filename)
        
        # Store the item data
        with open(item_path, "w") as f:
            if isinstance(item_data, dict) or isinstance(item_data, list):
                json.dump(item_data, f, indent=4)
            else:
                f.write(str(item_data))
                
        print(f"Stored item '{item_name}' for user {self.username}")
        return item_path

class AuthSystem:
    def __init__(self):
        self.blockchain = Blockchain()
        self.users = {}  # username -> {"role": role, "public_key": key, "private_key": key}
        self.db_manager = None  # Initialize as None first
        self.load_users_from_blockchain()  # This will properly set up the db_manager
    
    def load_users_from_blockchain(self):
        """Extract user data from blockchain"""
        self.users = {}
        for block in self.blockchain.chain:
            if block.data.get("action") == "register":
                username = block.data.get("username")
                role = block.data.get("role", "user")
                public_key = block.data.get("public_key")
                private_key = block.data.get("private_key")  # Encrypted
                
                self.users[username] = {
                    "role": role,
                    "public_key": public_key,
                    "private_key": private_key
                }
        
        # Now that users are loaded, initialize the database manager
        self.db_manager = blockchain_databases.DatabaseManager(self)
    
    def register_user(self, username, role, password):
        """Register a new user and add to blockchain"""
        if username in self.users:
            print("User already exists!")
            return False
        
        # Create new user with key pair
        user = User(username, role)
        
        # Store user data in blockchain
        block_data = {
            "action": "register",
            "username": username,
            "role": role,
            "public_key": user.get_public_key_pem(),
            "private_key": user.get_private_key_pem(password),  # Store encrypted private key
            "timestamp": time.time(),
            "previous": self.get_previous_user(username)  # Chain reference
        }
        
        new_block = Block(len(self.blockchain.chain), time.time(), block_data, "")
        self.blockchain.add_block(new_block)
        
        # Update users dictionary
        self.users[username] = {
            "role": role,
            "public_key": user.get_public_key_pem(),
            "private_key": user.get_private_key_pem(password)
        }
        
        print("User added successfully and recorded in blockchain.")
        return True
    
    def get_previous_user(self, current_user):
        """Get the previous user in chain (similar to the linked list structure)"""
        latest_block = self.blockchain.get_latest_block()
        # If this is not the genesis block and contains user data
        if latest_block.index > 0 and "username" in latest_block.data:
            return latest_block.data["username"]
        return None
    
    def authenticate(self, username, password):
        """Authenticate a user using password and blockchain verification"""
        if username not in self.users:
            print("User not found!")
            return None, None
        
        try:
            # Load the private key from storage
            private_key_pem = self.users[username]["private_key"]
            role = self.users[username]["role"]
            
            # Try to decrypt the private key with the password
            try:
                serialization.load_pem_private_key(
                    private_key_pem.encode('utf-8'),
                    password=password.encode('utf-8')
                )
                # If we get here, password was correct
                
                # Log authentication in blockchain
                block_data = {
                    "action": "authenticate",
                    "username": username,
                    "timestamp": time.time()
                }
                new_block = Block(len(self.blockchain.chain), time.time(), block_data, "")
                self.blockchain.add_block(new_block)
                
                # Verify blockchain integrity after adding authentication
                # If chain is compromised, this will trigger the fallback response
                if not self.blockchain.is_chain_valid():
                    return None, None
                
                print(f"Welcome, {username} ({role})!")
                return username, role
                
            except Exception:
                print("Authentication failed - incorrect password!")
                return None, None
                
        except Exception as e:
            print(f"Authentication error: {str(e)}")
            return None, None
    
    def list_users(self):
        """List all registered users in the chain order"""
        # Find the most recent user (head of the chain)
        head_user = None
        for block in reversed(self.blockchain.chain):
            if block.data.get("action") == "register":
                head_user = block.data.get("username")
                break
        
        if not head_user:
            print("No users registered yet.")
            return
        
        print("\nRegistered Users (in chain order):")
        current_user = head_user
        while current_user:
            if current_user in self.users:
                user_info = self.users[current_user]
                print(f"Username: {current_user}, Role: {user_info['role']}")
                
                # Find the previous user in the chain
                previous_user = None
                for block in self.blockchain.chain:
                    if block.data.get("action") == "register" and block.data.get("username") == current_user:
                        previous_user = block.data.get("previous")
                        break
                
                current_user = previous_user
            else:
                # This should not happen if blockchain is consistent
                print(f"Warning: User {current_user} found in chain but not in user records")
                break
    
    def verify_blockchain(self):
        """Verify the integrity of the blockchain"""
        if self.blockchain.is_chain_valid():
            print("Blockchain integrity verified - all blocks are valid.")
        else:
            print("WARNING: Blockchain integrity compromised - chain validation failed!")

def authenticate():
    """User authentication interface"""
    auth_system = AuthSystem()
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    
    auth_result = auth_system.authenticate(username, password)
    if auth_result[0]:
        return auth_result[0], auth_result[1], auth_system  # Only return username, role, and auth_system
    return None, None, None

def main_menu(username, user_role, auth_system, adjuster=None):
    """Main menu after successful login"""
    
    while True:
        print("\nBlockchain Authentication System")
        print("1. List Users")
        print("2. Add User (Admin Only)")
        print("3. Verify Blockchain Integrity")
        print("4. View Blockchain Records")
        print("5. Database Operations")
        print("6. User Item Management")
        print("7. Refresh Blockchain State")
        print("8. Logout")
        choice = input("Enter option: ")

        if choice == "1":
            auth_system.list_users()
            
        elif choice == "2" and user_role == "admin":
            new_user = input("Enter new username: ")
            new_role = input("Enter role (user/admin): ")
            new_pass = getpass.getpass("Enter new password: ")
            auth_system.register_user(new_user, new_role, new_pass)
            
            # Refresh blockchain state manually
            auth_system.blockchain.load_chain()
            auth_system.load_users_from_blockchain()
            auth_system.verify_blockchain()
            
        elif choice == "3":
            auth_system.verify_blockchain()
            
        elif choice == "4":
            print("\nBlockchain records:")
            for block in auth_system.blockchain.to_dict():
                block_data = block.get("data", {})
                action = block_data.get("action", "Unknown")
                username = block_data.get("username", "N/A")
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(block["timestamp"]))
                print(f"Block #{block['index']}: {action} - {username} ({timestamp})")
                
        elif choice == "5":
            database_menu(username, user_role, auth_system)
            
        elif choice == "6":
            user_item_menu(username, auth_system)
        
        elif choice == "7":
            # Manually refresh blockchain state
            auth_system.blockchain.load_chain()
            auth_system.load_users_from_blockchain()
            auth_system.verify_blockchain()
            print("Blockchain state refreshed successfully.")
            
        elif choice == "8":
            print("Logging out...")
            break
            
        else:
            print("Invalid option or insufficient privileges!")
            

def database_menu(username, user_role, auth_system):
    """Database operations menu"""
    def upload_to_selected_database(db_name, item_name):
        from file_upload_ui import FileUploadDialog
        upload_dialog = FileUploadDialog(title=f"Upload Files to {db_name}")
        selected_files = upload_dialog.show()
        
        if selected_files and len(selected_files) > 0:
            success_count = 0
            for file_path in selected_files:
                try:
                    # Create a unique filename for the item
                    timestamp = int(time.time())
                    file_ext = os.path.splitext(file_path)[1]
                    item_filename = f"{item_name}_{os.path.basename(file_path)}_{timestamp}{file_ext}"
                    
                    # Store the file in the database
                    stored_path = auth_system.db_manager.store_item(db_name, item_filename, file_path, username)
                    if stored_path:
                        print(f"✓ Stored: {os.path.basename(file_path)}")
                        success_count += 1
                    else:
                        print(f"✗ Failed to store: {os.path.basename(file_path)}")
                except Exception as e:
                    print(f"✗ Error storing {os.path.basename(file_path)}: {str(e)}")
            
            print(f"\nUpload complete. Successfully stored {success_count} out of {len(selected_files)} files.")
        else:
            print("No files selected. Operation cancelled.")

    while True:
        print("\nDatabase Operations")
        print("1. List Available Databases")
        print("2. Create New Database (Admin Only)")
        print("3. View Database Items")
        print("4. Add Item to Database")
        print("5. Return to Main Menu")
        print("6. Add user to a Database")
        choice = input("Enter option: ")
        
        if choice == "1":
            # List all databases (for admin) or user's databases
            databases = auth_system.db_manager.list_databases(username, user_role)
            if databases:
                print("\nAvailable Databases:")
                for idx, db in enumerate(databases, 1):
                    print(f"{idx}. {db['name']} (Owner: {db['owner']}, Created: {db['created_at']})")
            else:
                print("No databases available.")
                
        elif choice == "2" and user_role == "admin":
            # Create a new database
            db_name = input("Enter database name: ")
            
            # Simple schema definition
            schema = {"tables": {}}
            try:
                table_count = int(input("How many tables to create? "))
            except ValueError:
                print("Invalid input. Please enter a number.")
                continue
            
            for i in range(table_count):
                table_name = input(f"Enter name for table {i+1}: ")
                schema["tables"][table_name] = {"fields": {}}
                
                try:
                    field_count = int(input(f"How many fields in table '{table_name}'? "))
                except ValueError:
                    print("Invalid input. Please enter a number.")
                    continue
                    
                for j in range(field_count):
                    field_name = input(f"Enter name for field {j+1}: ")
                    field_type = input(f"Enter type for field '{field_name}' (string/int/float/bool): ")
                    schema["tables"][table_name]["fields"][field_name] = field_type
            
            # Create the database
            try:
                db_path = auth_system.db_manager.create_database(db_name, schema, username)
                if db_path:
                    print(f"Database '{db_name}' created successfully at {db_path}")
            except Exception as e:
                print(f"Error creating database: {str(e)}")
            
        elif choice == "3":
            # View database items
            databases = auth_system.db_manager.list_databases(username, user_role)
            if not databases:
                print("No databases available.")
                continue
                
            print("\nAvailable Databases:")
            for idx, db in enumerate(databases, 1):
                print(f"{idx}. {db['name']} (Owner: {db['owner']})")
                
            try:
                db_idx = int(input("Select database number: ")) - 1
                if db_idx < 0 or db_idx >= len(databases):
                    print("Invalid selection. Please enter a valid database number.")
                    continue
            except ValueError:
                print("Invalid input. Please enter a number.")
                continue
                
            selected_db = databases[db_idx]["name"]
            items = auth_system.db_manager.get_database_items(selected_db, username, user_role)
            
            if items:
                print(f"\nItems in '{selected_db}':")
                for idx, item in enumerate(items, 1):
                    print(f"{idx}. {item['name']} (Owner: {item['owner']}, Created: {item['created_at']})")
                    
                # Option to view item content
                view_item = input("View an item? (y/n): ").lower()
                if view_item == 'y':
                    try:
                        item_idx = int(input("Select item number: ")) - 1
                        if item_idx < 0 or item_idx >= len(items):
                            print("Invalid selection. Please enter a valid item number.")
                            continue
                    except ValueError:
                        print("Invalid input. Please enter a number.")
                        continue
                        
                    item_path = items[item_idx]["path"]
                    try:
                        # Check if it's a text-based file
                        if item_path.endswith(('.txt', '.json', '.py')):
                            with open(item_path, "r") as f:
                                content = f.read()
                                print(f"\nContent of '{items[item_idx]['name']}':")
                                print(content)
                        else:
                            print(f"\nFile '{items[item_idx]['name']}' is not a text file and cannot be displayed.")
                            print(f"File path: {item_path}")
                    except Exception as e:
                        print(f"Error reading item: {str(e)}")
            else:
                print(f"No items found in database '{selected_db}'.")
                
        elif choice == "4":
            # Add item to database
            databases = auth_system.db_manager.list_databases(username, user_role)
            if not databases:
                print("No databases available.")
                continue
                
            print("\nAvailable Databases:")
            for idx, db in enumerate(databases, 1):
                print(f"{idx}. {db['name']} (Owner: {db['owner']})")
                
            try:
                db_idx = int(input("Select database number: ")) - 1
                if db_idx < 0 or db_idx >= len(databases):
                    print("Invalid selection. Please enter a valid database number.")
                    continue
            except ValueError:
                print("Invalid input. Please enter a number.")
                continue
                
            selected_db = databases[db_idx]["name"]
            item_name = input("Enter item name: ")
            upload_to_selected_database(selected_db, item_name)
            
        elif choice == "5":
            break
            
        elif choice == "6":
            # Add user to database
            if user_role != "admin":
                print("Only administrators can add users to databases.")
                continue
                
            databases = auth_system.db_manager.list_databases(username, user_role)
            if not databases:
                print("No databases available.")
                continue
                
            print("\nAvailable Databases:")
            for idx, db in enumerate(databases, 1):
                print(f"{idx}. {db['name']} (Owner: {db['owner']})")
                
            try:
                db_idx = int(input("Select database number: ")) - 1
                if db_idx < 0 or db_idx >= len(databases):
                    print("Invalid selection. Please enter a valid database number.")
                    continue
            except ValueError:
                print("Invalid input. Please enter a number.")
                continue
                
            selected_db = databases[db_idx]["name"]
            
            # Get user details
            new_username = input("Enter username to add: ")
            new_role = input("Enter role for this user (user/admin): ").lower()
            
            if new_role not in ['user', 'admin']:
                print("Invalid role. Please enter 'user' or 'admin'.")
                continue
                
            # Add user to database
            try:
                success = auth_system.db_manager.add_user_to_database(selected_db, new_username, new_role, username)
                if success:
                    print(f"User '{new_username}' added successfully to database '{selected_db}'")
                else:
                    print(f"Failed to add user '{new_username}' to database '{selected_db}'")
            except Exception as e:
                print(f"Error adding user to database: {str(e)}")
            
        else:
            print("Invalid option or insufficient privileges!")

def user_item_menu(username, auth_system):
    """User item management menu"""
    def upload_to_user_folder():
        from file_upload_ui import FileUploadDialog
        upload_dialog = FileUploadDialog(title=f"Upload Files for {username}")
        selected_files = upload_dialog.show()
        
        if selected_files and len(selected_files) > 0:
            success_count = 0
            for file_path in selected_files:
                try:
                    # Create a unique filename for the item
                    timestamp = int(time.time())
                    file_ext = os.path.splitext(file_path)[1]
                    item_filename = f"{item_name}_{os.path.basename(file_path)}_{timestamp}{file_ext}"
                    item_path = os.path.join("userData", username, item_filename)
                    
                    # Ensure user folder exists
                    os.makedirs(os.path.dirname(item_path), exist_ok=True)
                    
                    # Copy the file
                    shutil.copy2(file_path, item_path)
                    print(f"✓ Stored: {os.path.basename(file_path)}")
                    success_count += 1
                    
                except Exception as e:
                    print(f"✗ Error storing {os.path.basename(file_path)}: {str(e)}")
            
            print(f"\nUpload complete. Successfully stored {success_count} out of {len(selected_files)} files.")
        else:
            print("No files selected. Operation cancelled.")

    while True:
        print("\nUser Item Management")
        print("1. List My Items")
        print("2. Store New Item")
        print("3. Return to Main Menu")
        choice = input("Enter option: ")
        
        if choice == "1":
            # Get user object from username
            user_obj = User(username, auth_system.users[username]["role"])
            user_folder = os.path.join("userData", username)
            
            if os.path.exists(user_folder):
                # List all files except user_info.json
                items = [f for f in os.listdir(user_folder) if f != 'user_info.json']
                
                if items:
                    print(f"\nItems for user '{username}':")
                    for idx, item in enumerate(items, 1):
                        item_path = os.path.join(user_folder, item)
                        try:
                            # Get file info
                            stat = os.stat(item_path)
                            size = format_size(stat.st_size)
                            modified = time.strftime("%Y-%m-%d %H:%M", time.localtime(stat.st_mtime))
                            print(f"{idx}. {item} (Size: {size}, Modified: {modified})")
                        except Exception as e:
                            print(f"{idx}. {item} (Error reading file info: {str(e)})")
                    
                    # Option to view item content
                    view_item = input("\nView an item? (y/n): ").lower()
                    if view_item == 'y':
                        item_idx = int(input("Select item number: ")) - 1
                        if item_idx >= 0 and item_idx < len(items):
                            item_path = os.path.join(user_folder, items[item_idx])
                            try:
                                # Check if it's a text-based file
                                if item_path.endswith(('.txt', '.json', '.py')):
                                    with open(item_path, "r") as f:
                                        content = f.read()
                                        print(f"\nContent of '{items[item_idx]}':")
                                        print(content)
                                else:
                                    print(f"\nFile '{items[item_idx]}' is not a text file and cannot be displayed.")
                                    print(f"File path: {item_path}")
                            except Exception as e:
                                print(f"Error reading item: {str(e)}")
                        else:
                            print("Invalid selection.")
                else:
                    print(f"No items found for user '{username}'.")
            else:
                print(f"User folder for '{username}' not found.")
                
        elif choice == "2":
            # Get user object from username
            user_obj = User(username, auth_system.users[username]["role"])
            
            # Get item name
            item_name = input("Enter item name: ")
            upload_to_user_folder()
            
        elif choice == "3":
            break
            
        else:
            print("Invalid option!")

def format_size(size_bytes):
    """Convert size in bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

# Initialize system with admin if blockchain is empty
def initialize_system():
    auth_system = AuthSystem()
    if len(auth_system.blockchain.chain) <= 1:  # Only genesis block exists
        print("Initializing system with admin user...")
        admin_password = getpass.getpass("Create admin password: ")
        auth_system.register_user("admin", "admin", admin_password)
        print("Admin user created. Please login.")
    
    # Initialize folders
    blockchain_databases.initialize_database_folders()
    return auth_system

# Test function to simulate blockchain tampering (for demonstration purposes)
def simulate_tampering():
    """Simulate tampering with the blockchain to trigger the fallback response"""
    print("\n[TEST] Simulating blockchain tampering...")
    try:
        blockchain = Blockchain()
        # Modify a block to trigger the fallback response
        if len(blockchain.chain) > 1:
            # Change data in a block
            blockchain.chain[1].data["username"] = "hacker"
            # Verify the chain to trigger the response
            is_valid = blockchain.is_chain_valid()
            print(f"[TEST] Blockchain integrity after tampering: {'Valid' if is_valid else 'Compromised'}")
        else:
            print("[TEST] Need at least 2 blocks to demonstrate tampering.")
    except Exception as e:
        print(f"[TEST] Error during tampering simulation: {str(e)}")

if __name__ == "__main__":
    # Initialize the system
    auth_system = initialize_system()
    
    adjuster = BlockAdjuster(auth_system.blockchain)
    
    # Authenticate user
    username, user_role, auth_system = authenticate()
    
    # If authentication successful, show main menu
    if username:
        main_menu(username, user_role, auth_system, adjuster)