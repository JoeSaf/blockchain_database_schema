from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import json
import time
from blockchain_databases import DatabaseStorage, DatabaseManager
from polymorphicblock import AuthSystem

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management

# Initialize authentication and database systems
auth_system = AuthSystem()
db_storage = DatabaseStorage()
db_manager = DatabaseManager(auth_system)

@app.route("/")
def home():
    """Homepage - lists available databases or redirects to login"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    databases = db_manager.list_databases(session['username'], session.get('role'))
    return render_template("home.html", databases=databases)

@app.route("/login", methods=["GET", "POST"])
def login():
    """User login page"""
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Authenticate user
        username, role = auth_system.authenticate(username, password)
        
        if username:
            session['username'] = username
            session['role'] = role
            flash(f"Welcome, {username}!")
            return redirect(url_for('home'))
        else:
            flash("Authentication failed. Please check your credentials.")
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    """Log out user"""
    session.pop('username', None)
    session.pop('role', None)
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route("/tables/<db_name>")
def list_tables(db_name):
    """List tables in a database"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Get the database path for the given name
    all_dbs = db_manager.list_databases(session['username'], session.get('role'))
    db = next((d for d in all_dbs if d["name"] == db_name), None)
    
    if not db:
        flash(f"Database '{db_name}' not found!")
        return redirect(url_for('home'))
    
    # Read the schema file to get tables
    schema_file = os.path.join(db["path"], "schema.json")
    if os.path.exists(schema_file):
        with open(schema_file, "r") as f:
            schema = json.load(f)
            tables = schema.get("tables", {}).keys()
    else:
        tables = []
    
    return render_template("tables.html", db_name=db_name, tables=list(tables))

@app.route("/table/<db_name>/<table_name>")
def view_table(db_name, table_name):
    """View records in a table"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Get database items from the blockchain
    items = db_manager.get_database_items(db_name, session['username'], session.get('role'))
    
    # Filter items that belong to the requested table
    table_items = []
    for item in items:
        try:
            with open(item["path"], "r") as f:
                data = json.load(f)
                if data.get("table") == table_name:
                    # Add item data and its ID to the table_items list
                    table_items.append({
                        "id": os.path.basename(item["path"]).split("_")[1].split(".")[0],
                        "data": data.get("data", {})
                    })
        except Exception as e:
            print(f"Error reading item {item['path']}: {str(e)}")
    
    # If we have any items, determine the columns from the first item
    columns = []
    rows = []
    if table_items:
        # Get column names from the first item's data
        if table_items[0]["data"] and isinstance(table_items[0]["data"], dict):
            columns = list(table_items[0]["data"].keys())
        
        # Format data as rows
        for item in table_items:
            if isinstance(item["data"], dict):
                row = [item["id"]] + [item["data"].get(col, "") for col in columns]
                rows.append(row)
    
    # Add ID column at the beginning
    columns = ["ID"] + columns
    
    return render_template("table_view.html", db_name=db_name, table_name=table_name, 
                          columns=columns, rows=rows)

@app.route("/delete/<db_name>/<table_name>/<item_id>", methods=["GET"])
def delete_record(db_name, table_name, item_id):
    """Delete a record from a table"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user has permissions to modify this database
    all_dbs = db_manager.list_databases(session['username'], session.get('role'))
    db = next((d for d in all_dbs if d["name"] == db_name), None)
    
    if not db:
        flash(f"Database '{db_name}' not found!")
        return redirect(url_for('home'))
    
    # Check if user is owner or admin
    user_role = session.get('role')
    if db["owner"] != session['username'] and user_role != "admin":
        flash("You don't have permission to modify this database!")
        return redirect(url_for('home'))
    
    # Find the item with the matching ID
    items = db_manager.get_database_items(db_name, session['username'], session.get('role'))
    for item in items:
        item_file_id = os.path.basename(item["path"]).split("_")[1].split(".")[0]
        if item_file_id == item_id:
            try:
                # Delete the file
                os.remove(item["path"])
                flash(f"Record deleted successfully.")
            except Exception as e:
                flash(f"Error deleting record: {str(e)}")
            break
    
    return redirect(url_for('view_table', db_name=db_name, table_name=table_name))

@app.route("/add/<db_name>/<table_name>", methods=["GET", "POST"])
def add_record(db_name, table_name):
    """Add a new record to a table"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Get database schema to determine fields
    all_dbs = db_manager.list_databases(session['username'], session.get('role'))
    db = next((d for d in all_dbs if d["name"] == db_name), None)
    
    if not db:
        flash(f"Database '{db_name}' not found!")
        return redirect(url_for('home'))
    
    # Read the schema file
    schema_file = os.path.join(db["path"], "schema.json")
    fields = []
    
    if os.path.exists(schema_file):
        with open(schema_file, "r") as f:
            schema = json.load(f)
            table_schema = schema.get("tables", {}).get(table_name, {})
            fields = table_schema.get("fields", {})
    
    if request.method == "POST":
        # Extract field values from form
        data = {}
        for field_name in fields:
            field_type = fields[field_name]
            value = request.form.get(field_name, "")
            
            # Convert value to appropriate type
            if field_type == "int":
                try:
                    data[field_name] = int(value)
                except ValueError:
                    data[field_name] = 0
            elif field_type == "float":
                try:
                    data[field_name] = float(value)
                except ValueError:
                    data[field_name] = 0.0
            elif field_type == "bool":
                data[field_name] = value.lower() in ("yes", "true", "1", "on")
            else:  # Default to string
                data[field_name] = value
        
        # Create item data structure
        item_data = {
            "table": table_name,
            "data": data,
            "created_at": time.time()
        }
        
        # Store the item in the database
        item_name = f"{table_name}_item"
        db_manager.store_item(db_name, item_name, item_data, session['username'])
        
        flash("Record added successfully!")
        return redirect(url_for('view_table', db_name=db_name, table_name=table_name))
    
    return render_template("add_record.html", db_name=db_name, table_name=table_name, fields=fields)

@app.route("/create_db", methods=["GET", "POST"])
def create_database():
    """Create a new database"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Only admin can create databases
    if session.get('role') != "admin":
        flash("Only admin users can create databases!")
        return redirect(url_for('home'))
    
    if request.method == "POST":
        db_name = request.form.get('db_name')
        table_count = int(request.form.get('table_count', 0))
        
        # Prepare schema
        schema = {"tables": {}}
        
        # Process each table
        for i in range(1, table_count + 1):
            table_name = request.form.get(f'table_name_{i}')
            field_count = int(request.form.get(f'field_count_{i}', 0))
            
            if table_name:
                schema["tables"][table_name] = {"fields": {}}
                
                # Process fields for this table
                for j in range(1, field_count + 1):
                    field_name = request.form.get(f'field_name_{i}_{j}')
                    field_type = request.form.get(f'field_type_{i}_{j}', 'string')
                    
                    if field_name:
                        schema["tables"][table_name]["fields"][field_name] = field_type
        
        # Create the database
        try:
            db_path = db_manager.create_database(db_name, schema, session['username'])
            if db_path:
                flash(f"Database '{db_name}' created successfully!")
                return redirect(url_for('home'))
            else:
                flash("Failed to create database.")
        except Exception as e:
            flash(f"Error creating database: {str(e)}")
    
    return render_template("create_database.html")

if __name__ == "__main__":
    app.run(port=1337, debug=True)