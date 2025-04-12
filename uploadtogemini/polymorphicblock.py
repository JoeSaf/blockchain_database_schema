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

# File to store blockchain data
BLOCKCHAIN_DB = "blockchain_db.json"
# Visible security script location
SECURITY_SCRIPT = "blockchain_security.py"

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
        if os.path.exists(BLOCKCHAIN_DB):
            self.load_chain()
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
                # Blockchain integrity compromised, trigger polymorphic response
                self._trigger_polymorphic_response("Hash mismatch detected")
                return False
            
            if current_block.previous_hash != previous_block.hash:
                # Blockchain integrity compromised, trigger polymorphic response
                self._trigger_polymorphic_response("Chain continuity broken")
                return False
                
        return True
    
    def _trigger_polymorphic_response(self, breach_reason):
        """Creates and executes a polymorphic security response when blockchain integrity is compromised"""
        print(f"WARNING: Blockchain integrity compromised - {breach_reason}")
        print("Initiating security response...")
        
        # Generate a new polymorphic security script
        def generate_polymorphic_script():
            # Create a payload for security response actions
            payload = f"""
import os
import json
import time
import hashlib
import socket
import platform
import random
import sys

# Security breach details
BREACH_DETAILS = {{
    "timestamp": {time.time()},
    "reason": "{breach_reason}",
    "blockchain_db": "{BLOCKCHAIN_DB}"
}}

# Create security report
def create_security_report():
    report = {{
        "timestamp": time.time(),
        "platform": platform.platform(),
        "hostname": socket.gethostname(),
        "username": os.getlogin(),
        "event": "blockchain_integrity_compromised",
        "reason": BREACH_DETAILS["reason"],
        "severity": "critical"
    }}
    
    # Hash the report for integrity verification
    report_hash = hashlib.sha256(json.dumps(report).encode()).hexdigest()
    report["report_hash"] = report_hash
    
    # Create a secure log file
    secure_log_path = "security_logs"
    os.makedirs(secure_log_path, exist_ok=True)
    
    log_file = os.path.join(secure_log_path, f"breach_{{int(time.time())}}.log")
    with open(log_file, "w") as f:
        json.dump(report, f, indent=4)
    
    print(f"Security breach details logged to {{log_file}}")
    return log_file

# Backup the blockchain file
def backup_blockchain():
    if os.path.exists("{BLOCKCHAIN_DB}"):
        backup_file = "{BLOCKCHAIN_DB}.bak.{{int(time.time())}}"
        try:
            with open("{BLOCKCHAIN_DB}", "r") as src:
                with open(backup_file, "w") as dst:
                    dst.write(src.read())
            print(f"Blockchain backup created: {{backup_file}}")
            return backup_file
        except Exception as e:
            print(f"Failed to backup blockchain: {{str(e)}}")
    return None

# Execute security measures
def execute_security_measures():
    print("Executing security response for blockchain integrity breach...")
    log_file = create_security_report()
    backup_file = backup_blockchain()
    
    # Notify about the security measures taken
    print("\\nSecurity Response Summary:")
    print(f"- Security breach logged: {{log_file}}")
    if backup_file:
        print(f"- Blockchain backup created: {{backup_file}}")
    print(f"- Next security variant will be generated")
    
    # Generate a new variant for next execution
    create_next_variant()

# Create the next polymorphic variant
def create_next_variant():
    # Generate a random identifier for the next variant
    variant_id = random.randint(1000, 9999)
    next_script = f"blockchain_security_{{variant_id}}.py"
    
    # Create the content for the next variant with some mutations
    with open(__file__, "r") as f:
        content = f.read()
    
    # Simple mutations to make each variant slightly different
    mutations = [
        # Randomize variable names
        ("create_security_report", f"generate_security_log_{{random.randint(100, 999)}}"),
        ("backup_blockchain", f"create_blockchain_backup_{{random.randint(100, 999)}}"),
        ("execute_security_measures", f"run_security_protocol_{{random.randint(100, 999)}}"),
        # Add random delay
        ("import time", "import time\\ntime.sleep(random.randint(1, 5))"),
        # Modify print statements
        ("Security breach details logged", f"Security incident recorded (variant: {{variant_id}})"),
        ("Blockchain backup created", f"Blockchain state preserved (variant: {{variant_id}})")
    ]
    
    # Apply mutations
    mutated_content = content
    for original, replacement in mutations:
        if original in mutated_content:
            mutated_content = mutated_content.replace(original, replacement)
    
    # Write the new variant
    with open(next_script, "w") as f:
        f.write(mutated_content)
    
    print(f"Next security variant created: {{next_script}}")
    
    # Make the new variant executable
    os.chmod(next_script, 0o755)

# Start execution
if __name__ == "__main__":
    execute_security_measures()
"""
            # Apply basic XOR encryption for some obfuscation
            key = random.randint(1, 255)
            
            # Fix: Properly encode and escape the encrypted payload string
            encrypted_payload = ""
            for c in payload:
                enc_char = chr(ord(c) ^ key)
                # Escape problematic characters in the string
                if enc_char == '"':
                    encrypted_payload += '\\"'
                elif enc_char == '\\':
                    encrypted_payload += '\\\\'
                elif enc_char == '\n':
                    encrypted_payload += '\\n'
                elif enc_char == '\r':
                    encrypted_payload += '\\r'
                elif enc_char == '\t':
                    encrypted_payload += '\\t'
                elif ord(enc_char) < 32 or ord(enc_char) > 126:
                    # Use unicode escape for non-printable characters
                    encrypted_payload += f'\\u{ord(enc_char):04x}'
                else:
                    encrypted_payload += enc_char
            
            # Create the decryption wrapper
            decryption_script = f"""
import os
import random
import time
import sys

print("Blockchain Security Response - Variant {random.randint(1000, 9999)}")

# Decrypt and execute the security payload
def run_security_protocol():
    # Decryption key and encrypted payload
    key = {key}
    encrypted_payload = "{encrypted_payload}"
    
    # Decrypt the payload
    decrypted_payload = ''
    for c in encrypted_payload:
        decrypted_payload += chr(ord(c) ^ key)
    
    # Execute the decrypted payload
    exec(decrypted_payload)

# Run the security protocol
if __name__ == "__main__":
    try:
        run_security_protocol()
    except Exception as e:
        print(f"Security protocol execution error: {{str(e)}}")
"""
            return decryption_script
        
        # Create the security script
        with open(SECURITY_SCRIPT, "w") as f:
            f.write(generate_polymorphic_script())
        
        # Make it executable
        os.chmod(SECURITY_SCRIPT, 0o755)
        
        # Execute the security response
        try:
            subprocess.Popen(["python", SECURITY_SCRIPT], 
                          stdout=subprocess.PIPE, 
                          stderr=subprocess.PIPE)
            print(f"Security response initiated. Check {SECURITY_SCRIPT} for details.")
        except Exception as e:
            print(f"Failed to execute security response: {str(e)}")
    
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
                # If chain is compromised, this will trigger the polymorphic response
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
    
    return auth_system.authenticate(username, password)

def main_menu(username, user_role):
    """Main menu after successful login"""
    auth_system = AuthSystem()
    
    while True:
        print("\nBlockchain Authentication System")
        print("1. List Users")
        print("2. Add User (Admin Only)")
        print("3. Verify Blockchain Integrity")
        print("4. View Blockchain Records")
        print("5. Database Operations")
        print("6. User Item Management")
        print("7. Logout")
        choice = input("Enter option: ")

        if choice == "1":
            auth_system.list_users()
            
        elif choice == "2" and user_role == "admin":
            new_user = input("Enter new username: ")
            new_role = input("Enter role (user/admin): ")
            new_pass = getpass.getpass("Enter new password: ")
            auth_system.register_user(new_user, new_role, new_pass)
            
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
            print("Logging out...")
            break
            
        else:
            print("Invalid option or insufficient privileges!")

def database_menu(username, user_role, auth_system):
    """Database operations menu"""
    while True:
        print("\nDatabase Operations")
        print("1. List Available Databases")
        print("2. Create New Database (Admin Only)")
        print("3. View Database Items")
        print("4. Add Item to Database")
        print("5. Return to Main Menu")
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
            table_count = int(input("How many tables to create? "))
            
            for i in range(table_count):
                table_name = input(f"Enter name for table {i+1}: ")
                schema["tables"][table_name] = {"fields": {}}
                
                field_count = int(input(f"How many fields in table '{table_name}'? "))
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
                
            db_idx = int(input("Select database number: ")) - 1
            if db_idx < 0 or db_idx >= len(databases):
                print("Invalid selection.")
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
                    item_idx = int(input("Select item number: ")) - 1
                    if item_idx >= 0 and item_idx < len(items):
                        item_path = items[item_idx]["path"]
                        try:
                            with open(item_path, "r") as f:
                                content = f.read()
                                print(f"\nContent of '{items[item_idx]['name']}':")
                                print(content)
                        except Exception as e:
                            print(f"Error reading item: {str(e)}")
                    else:
                        print("Invalid selection.")
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
                
            db_idx = int(input("Select database number: ")) - 1
            if db_idx < 0 or db_idx >= len(databases):
                print("Invalid selection.")
                continue
                
            selected_db = databases[db_idx]["name"]
            
            # Get item details
            item_name = input("Enter item name: ")
            print("Enter item data (JSON format):")
            item_data_str = input()
            
            try:
                item_data = json.loads(item_data_str)
                
                # Store the item
                item_path = auth_system.db_manager.store_item(selected_db, item_name, item_data, username)
                if item_path:
                    print(f"Item '{item_name}' stored successfully in database '{selected_db}'")
            except json.JSONDecodeError:
                print("Invalid JSON format. Item not stored.")
                
        elif choice == "5":
            break
            
        else:
            print("Invalid option or insufficient privileges!")

def user_item_menu(username, auth_system):
    """User item management menu"""
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
                items = [f for f in os.listdir(user_folder) if f.endswith('.json') and f != 'user_info.json']
                
                if items:
                    print(f"\nItems for user '{username}':")
                    for idx, item in enumerate(items, 1):
                        item_path = os.path.join(user_folder, item)
                        item_name = item.split('_')[0]  # Extract name from filename
                        print(f"{idx}. {item_name}")
                    
                    # Option to view item content
                    view_item = input("View an item? (y/n): ").lower()
                    if view_item == 'y':
                        item_idx = int(input("Select item number: ")) - 1
                        if item_idx >= 0 and item_idx < len(items):
                            item_path = os.path.join(user_folder, items[item_idx])
                            try:
                                with open(item_path, "r") as f:
                                    content = f.read()
                                    print(f"\nContent of '{items[item_idx]}':")
                                    print(content)
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
            
            # Get item details
            item_name = input("Enter item name: ")
            print("Enter item data (JSON format):")
            item_data_str = input()
            
            try:
                item_data = json.loads(item_data_str)
                
                # Store the item
                item_path = user_obj.store_user_item(item_name, item_data)
                print(f"Item '{item_name}' stored successfully at {item_path}")
            except json.JSONDecodeError:
                print("Invalid JSON format. Item not stored.")
                
        elif choice == "3":
            break
            
        else:
            print("Invalid option!")

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
    return auth_system  # Return the initialized auth_system


# Test function to simulate blockchain tampering (for demonstration purposes)
def simulate_tampering():
    """Simulate tampering with the blockchain to trigger the polymorphic response"""
    print("\n[TEST] Simulating blockchain tampering...")
    try:
        blockchain = Blockchain()
        # Modify a block to trigger the polymorphic response
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
    # Initialize the system and get the auth_system instance
    auth_system = initialize_system()
    
    # Authenticate user
    username, user_role = authenticate()
    
    # If authentication successful, show main menu
    if username:
        main_menu(username, user_role)