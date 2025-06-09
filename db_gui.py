# db_gui.py - Updated with Enhanced Dashboard Integration
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import json
import time
import csv
import io
from datetime import datetime
from blockchain_databases import DatabaseStorage, DatabaseManager
from polymorphicblock import AuthSystem

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management

# Initialize authentication and database systems
auth_system = AuthSystem()
db_storage = DatabaseStorage()
db_manager = DatabaseManager(auth_system)

# Get the blockchain instance from auth_system
blockchain = auth_system.blockchain

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

# ==================== ENHANCED DASHBOARD ROUTES ====================

@app.route("/blockchain")
def blockchain_dashboard():
    """Enhanced blockchain dashboard with advanced features"""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("blockchain_dashboard.html")

# ==================== ENHANCED API ENDPOINTS ====================

@app.route("/api/chain", methods=["GET"])
def get_chain():
    """Return the entire blockchain with enhanced metadata"""
    try:
        chain_data = blockchain.to_dict()
        
        # Add additional metadata for each block
        enhanced_chain = []
        for block in chain_data:
            enhanced_block = block.copy()
            
            # Add validation status for each block
            enhanced_block['is_valid'] = True  # You can implement actual validation logic
            
            # Add block size estimation
            enhanced_block['size_bytes'] = len(json.dumps(block))
            
            # Add time since creation
            if 'timestamp' in block:
                block_time = datetime.fromtimestamp(block['timestamp'])
                enhanced_block['age_human'] = format_time_ago(block_time)
            
            enhanced_chain.append(enhanced_block)
        
        return jsonify(enhanced_chain), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/status", methods=["GET"])
def get_status():
    """Get enhanced blockchain system status"""
    try:
        is_valid = blockchain.is_chain_valid()
        latest_block = blockchain.get_latest_block()
        
        # Calculate additional statistics
        user_count = count_unique_users()
        database_count = count_databases()
        
        # Get chain health metrics
        health_metrics = analyze_chain_health()
        
        status_data = {
            "status": "healthy" if is_valid else "corrupted",
            "chain_length": len(blockchain.chain),
            "latest_block": latest_block.to_dict() if latest_block else None,
            "unique_users": user_count,
            "total_databases": database_count,
            "health_metrics": health_metrics,
            "system_info": {
                "uptime": get_system_uptime(),
                "last_backup": get_last_backup_time(),
                "storage_usage": get_storage_usage()
            }
        }
        
        return jsonify(status_data), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/verify", methods=["POST"])
def verify_blockchain():
    """Perform comprehensive blockchain verification"""
    try:
        verification_results = {
            "timestamp": time.time(),
            "overall_status": "unknown",
            "checks": {}
        }
        
        # Basic chain validity
        basic_valid = blockchain.is_chain_valid()
        verification_results["checks"]["basic_validity"] = {
            "passed": basic_valid,
            "description": "Basic hash chain validation"
        }
        
        # Check for duplicate blocks
        duplicate_check = check_duplicate_blocks()
        verification_results["checks"]["duplicate_blocks"] = duplicate_check
        
        # Check timestamp consistency
        timestamp_check = check_timestamp_consistency()
        verification_results["checks"]["timestamp_consistency"] = timestamp_check
        
        # Check data integrity
        data_integrity_check = check_data_integrity()
        verification_results["checks"]["data_integrity"] = data_integrity_check
        
        # Determine overall status
        all_checks_passed = all(
            check["passed"] for check in verification_results["checks"].values()
        )
        verification_results["overall_status"] = "healthy" if all_checks_passed else "issues_detected"
        
        return jsonify(verification_results), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/analytics", methods=["GET"])
def get_blockchain_analytics():
    """Get detailed blockchain analytics"""
    try:
        analytics = {
            "block_types": analyze_block_types(),
            "user_activity": analyze_user_activity(),
            "temporal_analysis": analyze_temporal_patterns(),
            "size_analysis": analyze_chain_size(),
            "security_metrics": analyze_security_metrics()
        }
        
        return jsonify(analytics), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/export", methods=["POST"])
def export_blockchain():
    """Export blockchain data in various formats"""
    try:
        export_format = request.json.get('format', 'json') if request.json else 'json'
        include_metadata = request.json.get('include_metadata', True) if request.json else True
        
        chain_data = blockchain.to_dict()
        
        if include_metadata:
            # Add export metadata
            export_data = {
                "export_info": {
                    "timestamp": time.time(),
                    "format": export_format,
                    "chain_length": len(chain_data),
                    "exported_by": session.get('username', 'unknown')
                },
                "blockchain": chain_data
            }
        else:
            export_data = chain_data
        
        if export_format == 'json':
            return jsonify(export_data), 200
        elif export_format == 'csv':
            # Convert to CSV format
            csv_data = convert_blockchain_to_csv(chain_data)
            return csv_data, 200, {'Content-Type': 'text/csv'}
        else:
            return jsonify({"error": "Unsupported format"}), 400
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== UTILITY FUNCTIONS FOR DASHBOARD ====================

def format_time_ago(dt):
    """Format datetime as human-readable time ago"""
    now = datetime.now()
    diff = now - dt
    
    if diff.days > 0:
        return f"{diff.days} days ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hours ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minutes ago"
    else:
        return "Just now"

def count_unique_users():
    """Count unique users in the blockchain"""
    users = set()
    for block in blockchain.chain:
        if hasattr(block, 'data') and block.data.get('username'):
            users.add(block.data['username'])
    return len(users)

def count_databases():
    """Count databases created in the blockchain"""
    count = 0
    for block in blockchain.chain:
        if hasattr(block, 'data') and block.data.get('action') == 'create_database':
            count += 1
    return count

def analyze_chain_health():
    """Analyze blockchain health metrics"""
    metrics = {
        "hash_consistency": True,
        "timestamp_order": True,
        "data_integrity": True,
        "chain_continuity": True
    }
    
    # Check hash consistency
    for i in range(1, len(blockchain.chain)):
        current = blockchain.chain[i]
        previous = blockchain.chain[i-1]
        
        if hasattr(current, 'previous_hash') and hasattr(previous, 'hash'):
            if current.previous_hash != previous.hash:
                metrics["chain_continuity"] = False
        
        if hasattr(current, 'hash') and hasattr(current, 'calculate_hash'):
            if current.hash != current.calculate_hash():
                metrics["hash_consistency"] = False
        
        if hasattr(current, 'timestamp') and hasattr(previous, 'timestamp'):
            if current.timestamp < previous.timestamp:
                metrics["timestamp_order"] = False
    
    return metrics

def check_duplicate_blocks():
    """Check for duplicate blocks in the chain"""
    seen_hashes = set()
    duplicates = []
    
    for block in blockchain.chain:
        if hasattr(block, 'hash'):
            if block.hash in seen_hashes:
                duplicates.append(block.index if hasattr(block, 'index') else 'unknown')
            seen_hashes.add(block.hash)
    
    return {
        "passed": len(duplicates) == 0,
        "description": f"Check for duplicate blocks",
        "duplicates_found": duplicates
    }

def check_timestamp_consistency():
    """Check timestamp consistency across the chain"""
    inconsistencies = []
    
    for i in range(1, len(blockchain.chain)):
        current = blockchain.chain[i]
        previous = blockchain.chain[i-1]
        
        if (hasattr(current, 'timestamp') and hasattr(previous, 'timestamp') and 
            current.timestamp < previous.timestamp):
            inconsistencies.append({
                "block_index": current.index if hasattr(current, 'index') else i,
                "issue": "Timestamp earlier than previous block"
            })
    
    return {
        "passed": len(inconsistencies) == 0,
        "description": "Check timestamp ordering",
        "inconsistencies": inconsistencies
    }

def check_data_integrity():
    """Check data integrity in blocks"""
    issues = []
    
    for block in blockchain.chain:
        if not hasattr(block, 'data') or not isinstance(block.data, dict):
            issues.append({
                "block_index": block.index if hasattr(block, 'index') else 'unknown',
                "issue": "Invalid data format"
            })
        elif not block.data.get('action'):
            issues.append({
                "block_index": block.index if hasattr(block, 'index') else 'unknown',
                "issue": "Missing action field"
            })
    
    return {
        "passed": len(issues) == 0,
        "description": "Check data structure integrity",
        "issues": issues
    }

def analyze_block_types():
    """Analyze distribution of block types"""
    types = {}
    for block in blockchain.chain:
        if hasattr(block, 'data'):
            action = block.data.get('action', 'unknown')
            types[action] = types.get(action, 0) + 1
    return types

def analyze_user_activity():
    """Analyze user activity patterns"""
    activity = {}
    for block in blockchain.chain:
        if hasattr(block, 'data'):
            username = block.data.get('username')
            if username:
                if username not in activity:
                    activity[username] = {
                        "total_actions": 0,
                        "actions": {},
                        "first_seen": block.timestamp if hasattr(block, 'timestamp') else 0,
                        "last_seen": block.timestamp if hasattr(block, 'timestamp') else 0
                    }
                
                activity[username]["total_actions"] += 1
                if hasattr(block, 'timestamp'):
                    activity[username]["last_seen"] = max(activity[username]["last_seen"], block.timestamp)
                
                action = block.data.get('action', 'unknown')
                activity[username]["actions"][action] = activity[username]["actions"].get(action, 0) + 1
    
    return activity

def analyze_temporal_patterns():
    """Analyze temporal patterns in the blockchain"""
    if len(blockchain.chain) < 2:
        return {"average_block_time": 0, "block_frequency": []}
    
    intervals = []
    for i in range(1, len(blockchain.chain)):
        if (hasattr(blockchain.chain[i], 'timestamp') and 
            hasattr(blockchain.chain[i-1], 'timestamp')):
            interval = blockchain.chain[i].timestamp - blockchain.chain[i-1].timestamp
            intervals.append(interval)
    
    avg_interval = sum(intervals) / len(intervals) if intervals else 0
    
    first_timestamp = blockchain.chain[0].timestamp if hasattr(blockchain.chain[0], 'timestamp') else 0
    last_timestamp = blockchain.chain[-1].timestamp if hasattr(blockchain.chain[-1], 'timestamp') else 0
    
    return {
        "average_block_time": avg_interval,
        "total_timespan": last_timestamp - first_timestamp,
        "blocks_per_hour": 3600 / avg_interval if avg_interval > 0 else 0
    }

def analyze_chain_size():
    """Analyze blockchain size metrics"""
    total_size = 0
    block_sizes = []
    
    for block in blockchain.chain:
        if hasattr(block, 'to_dict'):
            block_size = len(json.dumps(block.to_dict()))
        else:
            block_size = len(str(block))
        total_size += block_size
        block_sizes.append(block_size)
    
    return {
        "total_size_bytes": total_size,
        "average_block_size": total_size / len(blockchain.chain) if blockchain.chain else 0,
        "largest_block_size": max(block_sizes) if block_sizes else 0,
        "smallest_block_size": min(block_sizes) if block_sizes else 0
    }

def analyze_security_metrics():
    """Analyze security-related metrics"""
    auth_attempts = 0
    failed_blocks = 0
    
    for block in blockchain.chain:
        if hasattr(block, 'data') and block.data.get('action') == 'authenticate':
            auth_attempts += 1
        
        # Check if block hash is valid
        if (hasattr(block, 'hash') and hasattr(block, 'calculate_hash') and 
            block.hash != block.calculate_hash()):
            failed_blocks += 1
    
    return {
        "authentication_attempts": auth_attempts,
        "failed_blocks": failed_blocks,
        "integrity_score": (len(blockchain.chain) - failed_blocks) / len(blockchain.chain) if blockchain.chain else 1
    }

def convert_blockchain_to_csv(chain_data):
    """Convert blockchain data to CSV format"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Index', 'Timestamp', 'Action', 'Username', 'Hash', 'Previous Hash'])
    
    # Write data
    for block in chain_data:
        writer.writerow([
            block.get('index', ''),
            block.get('timestamp', ''),
            block.get('data', {}).get('action', ''),
            block.get('data', {}).get('username', ''),
            block.get('hash', ''),
            block.get('previous_hash', '')
        ])
    
    return output.getvalue()

def get_system_uptime():
    """Get system uptime (placeholder)"""
    return "System uptime tracking would be implemented here"

def get_last_backup_time():
    """Get last backup time (placeholder)"""
    return "Last backup tracking would be implemented here"

def get_storage_usage():
    """Get storage usage statistics"""
    try:
        # Calculate file sizes - check both locations
        blockchain_file_size = 0
        
        # Check for blockchain files
        possible_files = ["blockchain_db.json", "system_chains/active/blockchain_db.json"]
        for file_path in possible_files:
            if os.path.exists(file_path):
                blockchain_file_size += os.path.getsize(file_path)
        
        return {
            "blockchain_file_size": blockchain_file_size,
            "total_storage": f"{blockchain_file_size} bytes"
        }
    except Exception:
        return {"error": "Unable to calculate storage usage"}

# ==================== EXISTING TABLE/DATABASE ROUTES ====================
# (Keep all your existing table and database routes)

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


@app.route("/create_database", methods=["GET", "POST"])
def create_database():
    """Create a new database with enhanced error handling and validation"""
    if 'username' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))
    
    # Only admin can create databases
    if session.get('role') != "admin":
        flash("Only admin users can create databases!")
        return redirect(url_for('home'))
    
    if request.method == "POST":
        try:
            # Get database name
            db_name = request.form.get('db_name', '').strip()
            if not db_name:
                flash("Database name is required!")
                return render_template("create_database.html")
            
            # Validate database name
            if not db_name.replace('_', '').replace('-', '').isalnum():
                flash("Database name can only contain letters, numbers, underscores, and hyphens!")
                return render_template("create_database.html")
            
            # Check if database already exists
            existing_databases = db_manager.list_databases(session['username'], session.get('role'))
            if any(db['name'] == db_name for db in existing_databases):
                flash(f"Database '{db_name}' already exists! Please choose a different name.")
                return render_template("create_database.html")
            
            # Get table count
            table_count = int(request.form.get('table_count', 0))
            if table_count < 1:
                flash("Database must have at least one table!")
                return render_template("create_database.html")
            
            # Prepare schema
            schema = {"tables": {}}
            
            # Process each table
            for i in range(1, table_count + 1):
                table_name = request.form.get(f'table_name_{i}', '').strip()
                if not table_name:
                    flash(f"Table {i} name is required!")
                    return render_template("create_database.html")
                
                # Validate table name
                if not table_name.replace('_', '').isalnum():
                    flash(f"Table name '{table_name}' can only contain letters, numbers, and underscores!")
                    return render_template("create_database.html")
                
                # Check for duplicate table names
                if table_name in schema["tables"]:
                    flash(f"Duplicate table name '{table_name}' found! Table names must be unique.")
                    return render_template("create_database.html")
                
                field_count = int(request.form.get(f'field_count_{i}', 0))
                if field_count < 1:
                    flash(f"Table '{table_name}' must have at least one field!")
                    return render_template("create_database.html")
                
                schema["tables"][table_name] = {"fields": {}}
                
                # Process fields for this table
                table_field_names = set()
                for j in range(1, field_count + 1):
                    field_name = request.form.get(f'field_name_{i}_{j}', '').strip()
                    field_type = request.form.get(f'field_type_{i}_{j}', 'string')
                    
                    if not field_name:
                        flash(f"All fields in table '{table_name}' must have names!")
                        return render_template("create_database.html")
                    
                    # Validate field name
                    if not field_name.replace('_', '').isalnum():
                        flash(f"Field name '{field_name}' can only contain letters, numbers, and underscores!")
                        return render_template("create_database.html")
                    
                    # Check for duplicate field names within the table
                    if field_name in table_field_names:
                        flash(f"Duplicate field name '{field_name}' in table '{table_name}'! Field names must be unique within each table.")
                        return render_template("create_database.html")
                    
                    table_field_names.add(field_name)
                    
                    # Validate field type
                    valid_types = ['string', 'int', 'float', 'bool']
                    if field_type not in valid_types:
                        field_type = 'string'  # Default to string if invalid type
                    
                    schema["tables"][table_name]["fields"][field_name] = field_type
            
            # Create the database
            print(f"Creating database '{db_name}' with schema: {schema}")
            db_path = db_manager.create_database(db_name, schema, session['username'])
            
            if db_path:
                flash(f"Database '{db_name}' created successfully with {table_count} table(s)!")
                print(f"Database created at: {db_path}")
                return redirect(url_for('home'))
            else:
                flash("Failed to create database. Please try again.")
                print("Database creation failed - no path returned")
                
        except ValueError as ve:
            flash(f"Invalid input: {str(ve)}")
            print(f"ValueError in create_database: {str(ve)}")
        except Exception as e:
            flash(f"Error creating database: {str(e)}")
            print(f"Exception in create_database: {str(e)}")
            import traceback
            traceback.print_exc()
    
    return render_template("create_database.html")

# Also add this route to handle the /create_db URL (alternative endpoint)
@app.route("/create_db", methods=["GET", "POST"])
def create_db():
    """Alternative endpoint for create database"""
    return create_database()

# Add this debugging route to check what routes are available
@app.route("/debug/routes")
def debug_routes():
    """Debug route to show all available routes"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    import urllib.parse
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        line = urllib.parse.unquote(f"{rule.endpoint:30s} {methods:20s} {rule}")
        output.append(line)
    
    response = app.make_response("<br>".join(sorted(output)))
    response.headers["content-type"] = "text/html"
    return response
if __name__ == "__main__":
    app.run(port=1337, debug=True)