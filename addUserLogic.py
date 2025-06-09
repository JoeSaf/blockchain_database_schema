from polymorphicblock import AuthSystem
from polymorphicblock import Blockchain
import blockchain_databases
import polymorphicblock

auth_instance = AuthSystem()
AuthSystem.database_menu()
blockchaindb = Blockchain()
"""this code deals with creating users to a database"""
if (choice == "6"):
    get_db = input("To what database: ")
    
    # Check if the entered database exists in your system
    if get_db in dir(blockchain_databases):
        new_user = input("Enter new username: ")
        new_role = input("Enter role (user/admin): ").lower()
        
        if new_role not in ['user', 'admin']:
            print("Invalid role. Please enter 'user' or 'admin'.")
        else:
            # Assuming blockchaindb has a method to write users
            blockchaindb.write(new_user, role=new_role)
    else:
        print(f"Database '{get_db}' does not exist.")
else:
    print("Failed to create new user.")