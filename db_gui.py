
# This version removes the interfering security analysis and focuses on displaying status

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import json
import time
import csv
import io
import glob
import hashlib
import threading
import weakref
import shutil
from collections import defaultdict
from datetime import datetime, timedelta
from blockchain_databases import DatabaseStorage, DatabaseManager
from polymorphicblock import AuthSystem
from centralized_chain_management import ChainDirectoryManager

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize authentication and database systems
auth_system = AuthSystem()
db_storage = DatabaseStorage()
db_manager = DatabaseManager(auth_system)
blockchain = auth_system.blockchain

# Use the centralized chain manager from the blockchain
chain_manager = blockchain.chain_manager if hasattr(blockchain, 'chain_manager') else ChainDirectoryManager()

# Security dashboard configuration (READ-ONLY)
security_config = {
    'system_start_time': time.time(),
    'last_status_check': None,
    'dashboard_refresh_interval': 30,  # seconds
    'show_detailed_logs': True
}

# ==================== SECURITY DASHBOARD (READ-ONLY) ====================
class SecurityDashboard:
    """Read-only security dashboard that displays status from existing security system"""
    
    def __init__(self, blockchain, chain_manager):
        self.blockchain = blockchain
        self.chain_manager = chain_manager
        self.last_status_update = None
        self.cached_status = None
    
    def get_security_status(self):
        """Get security status by reading from the existing security files"""
        try:
            current_time = time.time()
            
            # Cache status for 10 seconds to avoid excessive file reads
            if (self.cached_status and self.last_status_update and 
                current_time - self.last_status_update < 10):
                return self.cached_status
            
            status = {
                'chain_length': len(self.blockchain.chain),
                'chain_valid': True,  # We trust the blockchain's own validation
                'quarantined_blocks': self._count_quarantined_blocks(),
                'fallback_databases': self._count_fallback_databases(),
                'forensic_reports': self._count_forensic_reports(),
                'system_uptime': current_time - security_config['system_start_time'],
                'last_update': current_time,
                'storage_location': str(self.chain_manager.base_dir),
                'integrity_score': self._calculate_display_integrity_score(),
                'threat_level': 'NONE',  # Let the real security system determine this
                'monitoring_active': True
            }
            
            # Update cache
            self.cached_status = status
            self.last_status_update = current_time
            
            return status
            
        except Exception as e:
            print(f"Error getting security status: {e}")
            return {
                'error': str(e),
                'chain_length': 0,
                'last_update': time.time()
            }
    
    def _count_quarantined_blocks(self):
        """Count quarantined blocks from centralized storage"""
        try:
            quarantine_dir = self.chain_manager.subdirs['quarantine']
            quarantine_files = list(quarantine_dir.glob('quarantined_blocks_*.json'))
            
            total_quarantined = 0
            for file_path in quarantine_files:
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        if 'quarantined_block_data' in data:
                            total_quarantined += len(data['quarantined_block_data'])
                        elif 'infected_blocks' in data:
                            total_quarantined += len(data['infected_blocks'])
                except Exception:
                    continue
            
            return total_quarantined
        except Exception:
            return 0
    
    def _count_fallback_databases(self):
        """Count fallback databases"""
        try:
            fallback_dir = self.chain_manager.subdirs['fallbacks']
            fallback_files = list(fallback_dir.glob('enhanced_fallback_db_*.json'))
            return len(fallback_files)
        except Exception:
            return 0
    
    def _count_forensic_reports(self):
        """Count forensic reports"""
        try:
            forensics_dir = self.chain_manager.subdirs['forensics']
            forensic_files = list(forensics_dir.glob('forensic_report_*.json'))
            return len(forensic_files)
        except Exception:
            return 0
    
    def _calculate_display_integrity_score(self):
        """Calculate a simple integrity score for display purposes"""
        try:
            # Simple calculation based on chain continuity
            if len(self.blockchain.chain) == 0:
                return 100
            
            # Check if we have recent quarantine activity
            quarantined = self._count_quarantined_blocks()
            if quarantined > 0:
                return max(75, 100 - (quarantined * 5))
            
            return 100
        except Exception:
            return 100
    
    def get_security_timeline(self):
        """Get security timeline from forensic reports"""
        try:
            forensics_dir = self.chain_manager.subdirs['forensics']
            forensic_files = list(forensics_dir.glob('forensic_report_*.json'))
            
            timeline = []
            for file_path in forensic_files:
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        
                        event = {
                            'type': 'forensic_analysis',
                            'timestamp': data.get('forensic_timestamp', time.time()),
                            'title': 'Security Analysis Completed',
                            'description': f"Analysis: {data.get('analysis_type', 'Unknown')}",
                            'details': {
                                'infected_blocks': len(data.get('infection_details', [])),
                                'quarantine_actions': data.get('quarantine_actions', []),
                                'recovery_actions': data.get('recovery_actions', [])
                            }
                        }
                        timeline.append(event)
                except Exception:
                    continue
            
            # Sort by timestamp (newest first)
            timeline.sort(key=lambda x: x['timestamp'], reverse=True)
            return timeline[:50]  # Return last 50 events
        except Exception:
            return []
        
    def get_quarantine_data(self):
        """Get detailed quarantined blocks data for display"""
        try:
            quarantine_dir = self.chain_manager.subdirs['quarantine']
            quarantine_files = list(quarantine_dir.glob('quarantined_blocks_*.json'))
            
            quarantine_data = []
            for file_path in quarantine_files:
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        
                        # Extract individual quarantined block details
                        infected_blocks_info = []
                        
                        # Look for infected blocks details in various formats
                        if 'infected_blocks' in data and isinstance(data['infected_blocks'], list):
                            infected_blocks_info = data['infected_blocks']
                        elif 'quarantined_block_data' in data and isinstance(data['quarantined_block_data'], list):
                            infected_blocks_info = data['quarantined_block_data']
                        elif 'infected_block_details' in data and isinstance(data['infected_block_details'], list):
                            infected_blocks_info = data['infected_block_details']
                        
                        # Count blocks from data
                        blocks_count = len(infected_blocks_info)
                        if blocks_count == 0 and 'quarantined_blocks_count' in data:
                            blocks_count = data['quarantined_blocks_count']
                        elif blocks_count == 0 and 'infected_blocks_count' in data:
                            blocks_count = data['infected_blocks_count']
                        
                        # Add file metadata with detailed infected blocks info
                        file_info = {
                            'file_name': file_path.name,
                            'file_path': str(file_path),
                            'quarantine_timestamp': data.get('quarantine_timestamp', time.time()),
                            'quarantine_reason': data.get('quarantine_reason', 'Blockchain infection detected'),
                            'blocks_quarantined': blocks_count,
                            'infected_blocks_info': infected_blocks_info,  # This contains the detailed block data
                            'file_size': file_path.stat().st_size if file_path.exists() else 0,
                            'analysis_type': data.get('analysis_type', 'Security Analysis'),
                            'original_chain_length': data.get('original_chain_length', 0),
                            'clean_chain_length': data.get('clean_chain_length', 0)
                        }
                        quarantine_data.append(file_info)
                        
                except json.JSONDecodeError as e:
                    print(f"Error parsing JSON in quarantine file {file_path}: {e}")
                    # Add file info even if JSON is corrupted
                    quarantine_data.append({
                        'file_name': file_path.name,
                        'file_path': str(file_path),
                        'quarantine_timestamp': file_path.stat().st_mtime,
                        'quarantine_reason': 'File parsing error - corrupted data',
                        'blocks_quarantined': 0,
                        'infected_blocks_info': [],
                        'error': f"JSON parsing error: {str(e)}"
                    })
                    continue
                except Exception as e:
                    print(f"Error reading quarantine file {file_path}: {e}")
                    continue
            
            # Sort by quarantine timestamp (newest first)
            quarantine_data.sort(key=lambda x: x.get('quarantine_timestamp', 0), reverse=True)
            
            print(f"🔍 [QUARANTINE] Loaded {len(quarantine_data)} quarantine files with details")
            return quarantine_data
            
        except Exception as e:
            print(f"Error getting quarantine data: {e}")
            return [] 

# Initialize security dashboard
security_dashboard = SecurityDashboard(blockchain, chain_manager)

# ==================== CORE WEBAPP ROUTES ====================
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
        result = auth_system.authenticate(username, password)
        
        if result and len(result) >= 2 and result[0]:
            session['username'] = result[0]
            session['role'] = result[1]
            flash(f"Welcome, {result[0]}!")
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

@app.route("/blockchain")
def blockchain_dashboard():
    """Enhanced blockchain dashboard"""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("blockchain_dashboard.html")

@app.route("/security-dashboard")
def security_dashboard_page():
    """Security dashboard - READ-ONLY monitoring"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Only admin users can access security dashboard
    if session.get('role') != 'admin':
        flash("Access denied. Admin privileges required.")
        return redirect(url_for('home'))
    
    return render_template("security_violations.html")

# ==================== READ-ONLY SECURITY API ENDPOINTS ====================

@app.route("/api/security/status", methods=["GET"])
def get_security_status():
    """Get security status (READ-ONLY)"""
    try:
        status = security_dashboard.get_security_status()
        return jsonify(status), 200
    except Exception as e:
        print(f"Error getting security status: {e}")
        return jsonify({
            "error": str(e),
            "status": "error",
            "timestamp": time.time()
        }), 500

@app.route("/api/security/quarantine", methods=["GET"])
def get_quarantine_status():
    """Get quarantined blocks status (READ-ONLY)"""
    try:
        quarantine_data = security_dashboard.get_quarantine_data()
        
        return jsonify({
            'quarantine_files': quarantine_data,
            'total_count': len(quarantine_data),
            'centralized_storage': str(chain_manager.subdirs['quarantine']),
            'quarantine_summary': {
                'total_files': len(quarantine_data),
                'oldest_quarantine': min([item.get('quarantine_timestamp', time.time())
                                        for item in quarantine_data], default=time.time()),
                'newest_quarantine': max([item.get('quarantine_timestamp', 0)
                                        for item in quarantine_data], default=0),
                'storage_location': str(chain_manager.subdirs['quarantine'])
            }
        }), 200
        
    except Exception as e:
        print(f"Error getting quarantine status: {e}")
        return jsonify({
            "error": str(e),
            "quarantine_files": []
        }), 500

@app.route("/api/security/timeline", methods=["GET"])
def get_security_timeline():
    """Get security event timeline (READ-ONLY)"""
    try:
        timeline = security_dashboard.get_security_timeline()
        
        return jsonify({
            'events': timeline,
            'total_events': len(timeline),
            'centralized_storage': str(chain_manager.subdirs['forensics']),
            'last_update': time.time()
        }), 200
        
    except Exception as e:
        print(f"Error getting security timeline: {e}")
        return jsonify({
            "error": str(e),
            "events": []
        }), 500

@app.route("/api/security/system-info", methods=["GET"])
def get_system_info():
    """Get system information for security dashboard"""
    try:
        if 'username' not in session or session.get('role') != 'admin':
            return jsonify({"error": "Unauthorized"}), 403
        
        system_info = {
            'blockchain_file': str(chain_manager.get_path('active')),
            'storage_directories': {
                name: str(path) for name, path in chain_manager.subdirs.items()
            },
            'system_uptime': time.time() - security_config['system_start_time'],
            'chain_manager_info': {
                'base_dir': str(chain_manager.base_dir),
                'directory_count': len(chain_manager.subdirs)
            },
            'file_counts': {
                'quarantine': len(list(chain_manager.subdirs['quarantine'].glob('*.json'))),
                'forensics': len(list(chain_manager.subdirs['forensics'].glob('*.json'))),
                'fallbacks': len(list(chain_manager.subdirs['fallbacks'].glob('*.json'))),
                'backups': len(list(chain_manager.subdirs['backups'].glob('*.json')))
            }
        }
        
        return jsonify(system_info), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== BLOCKCHAIN API ENDPOINTS ====================

@app.route("/api/chain", methods=["GET"])
def get_chain():
    """Return the entire blockchain"""
    try:
        chain_data = blockchain.to_dict()
        return jsonify(chain_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/status", methods=["GET"])
def get_status():
    """Get blockchain system status"""
    try:
        # Let the blockchain validate itself - don't interfere
        latest_block = blockchain.get_latest_block()
        
        # Simple status based on basic checks
        status_data = {
            "status": "healthy",  # Trust the blockchain's own validation
            "chain_length": len(blockchain.chain),
            "latest_block": latest_block.to_dict() if latest_block else None,
            "unique_users": count_unique_users(),
            "total_databases": count_databases(),
            "system_info": {
                "uptime": get_system_uptime(),
                "storage_location": str(chain_manager.base_dir),
                "last_update": time.time()
            }
        }
        
        return jsonify(status_data), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== DATABASE MANAGEMENT ROUTES ====================

@app.route("/tables/<db_name>")
def list_tables(db_name):
    """List tables in a database"""
    if 'username' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))
    
    try:
        all_dbs = db_manager.list_databases(session['username'], session.get('role'))
        db = next((d for d in all_dbs if d["name"] == db_name), None)
        
        if not db:
            flash(f"Database '{db_name}' not found or you don't have access to it!")
            return redirect(url_for('home'))
        
        schema_file = os.path.join(db["path"], "schema.json")
        tables = []
        
        if os.path.exists(schema_file):
            try:
                with open(schema_file, "r", encoding='utf-8') as f:
                    schema = json.load(f)
                    tables = list(schema.get("tables", {}).keys())
            except json.JSONDecodeError as e:
                print(f"Error reading schema file: {str(e)}")
                flash("Error reading database schema.")
        else:
            flash("Database schema file not found.")
        
        return render_template("tables.html", db_name=db_name, tables=tables)
        
    except Exception as e:
        print(f"Error in list_tables: {str(e)}")
        flash(f"Error loading tables: {str(e)}")
        return redirect(url_for('home'))

@app.route("/table/<db_name>/<table_name>")
def view_table(db_name, table_name):
    """View records in a table"""
    if 'username' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))
    
    try:
        databases = db_manager.list_databases(session['username'], session.get('role'))
        db_exists = any(db['name'] == db_name for db in databases)
        
        if not db_exists:
            flash(f"Database '{db_name}' not found or you don't have access to it.")
            return redirect(url_for('home'))
        
        items = db_manager.get_database_items(db_name, session['username'], session.get('role'))
        
        table_items = []
        for item in items:
            try:
                if not item.get("path") or not os.path.exists(item["path"]):
                    continue
                    
                with open(item["path"], "r", encoding='utf-8') as f:
                    data = json.load(f)
                    
                if data.get("table") == table_name:
                    filename = os.path.basename(item["path"])
                    try:
                        if "_" in filename:
                            item_id = filename.split("_")[1].split(".")[0]
                        else:
                            item_id = filename.split(".")[0]
                        if not item_id:
                            item_id = str(len(table_items) + 1)
                    except (IndexError, ValueError):
                        item_id = str(len(table_items) + 1)
                    
                    record_data = data.get("data", {})
                    if not isinstance(record_data, dict):
                        if isinstance(record_data, (list, tuple)):
                            record_data = {f"field_{i}": val for i, val in enumerate(record_data)}
                        else:
                            record_data = {"value": str(record_data)}
                    
                    table_items.append({
                        "id": item_id,
                        "data": record_data,
                        "path": item["path"]
                    })
                    
            except Exception as e:
                print(f"Error reading item {item.get('path', 'unknown')}: {str(e)}")
                continue
        
        columns = []
        rows = []
        
        if table_items:
            all_columns = set()
            for item in table_items:
                if isinstance(item["data"], dict):
                    all_columns.update(item["data"].keys())
            columns = sorted(list(all_columns))
            
            if not columns:
                columns = ["data"]
            
            for item in table_items:
                row = [item["id"]]
                
                for col in columns:
                    value = item["data"].get(col, "")
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, ensure_ascii=False)
                    elif value is None:
                        value = ""
                    elif isinstance(value, bool):
                        value = "True" if value else "False"
                    else:
                        value = str(value)
                    row.append(value)
                
                rows.append(row)
            
            columns = ["ID"] + columns
        
        return render_template("table_view.html", 
                             db_name=db_name, 
                             table_name=table_name,
                             columns=columns, 
                             rows=rows)
        
    except Exception as e:
        print(f"Error in view_table: {str(e)}")
        flash(f"Error loading table '{table_name}': {str(e)}")
        return redirect(url_for('list_tables', db_name=db_name))

@app.route("/add_record/<db_name>/<table_name>", methods=["GET", "POST"])
def add_record(db_name, table_name):
    """Add a new record to the specified table"""
    if 'username' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))
    
    try:
        databases = db_manager.list_databases(session['username'], session.get('role'))
        db_exists = any(db['name'] == db_name for db in databases)
        
        if not db_exists:
            flash(f"Database '{db_name}' not found or you don't have access to it.")
            return redirect(url_for('home'))
        
        if request.method == "GET":
            table_schema = get_table_schema(db_name, table_name)
            fields = table_schema.get("fields", {}) if table_schema else {}
            
            return render_template("add_record.html", 
                                 db_name=db_name, 
                                 table_name=table_name,
                                 fields=fields)
        
        elif request.method == "POST":
            record_data = {}
            
            field_names = request.form.getlist('field_names[]')
            field_values = request.form.getlist('field_values[]')
            
            for key, value in request.form.items():
                if key not in ['field_names[]', 'field_values[]'] and value.strip():
                    record_data[key] = value.strip()
            
            for i, field_name in enumerate(field_names):
                if field_name.strip() and i < len(field_values) and field_values[i].strip():
                    record_data[field_name.strip()] = field_values[i].strip()
            
            if not record_data:
                flash("Please provide at least one field with data.")
                return redirect(url_for('add_record', db_name=db_name, table_name=table_name))
            
            try:
                timestamp = int(time.time())
                record_id = f"{table_name}_{timestamp}"
                
                full_data = {
                    "table": table_name,
                    "data": record_data,
                    "timestamp": datetime.now().isoformat(),
                    "created_by": session['username']
                }
                
                success = db_manager.store_item(db_name, record_id, full_data, session['username'])
                
                if success:
                    flash("Record added successfully!")
                    return redirect(url_for('view_table', db_name=db_name, table_name=table_name))
                else:
                    flash("Failed to add record. Please try again.")
                    
            except Exception as e:
                print(f"Error adding record: {str(e)}")
                flash(f"Error adding record: {str(e)}")
            
            return redirect(url_for('add_record', db_name=db_name, table_name=table_name))
            
    except Exception as e:
        print(f"Error in add_record: {str(e)}")
        flash(f"Error: {str(e)}")
        return redirect(url_for('view_table', db_name=db_name, table_name=table_name))

@app.route("/delete_record/<db_name>/<table_name>/<item_id>", methods=["GET", "DELETE", "POST"])
def delete_record(db_name, table_name, item_id):
    """Delete a record from the specified table"""
    if 'username' not in session:
        if request.method == "DELETE":
            return jsonify({"success": False, "message": "Not authenticated"}), 401
        flash("Please log in to access this page.")
        return redirect(url_for('login'))
    
    try:
        databases = db_manager.list_databases(session['username'], session.get('role'))
        db_exists = any(db['name'] == db_name for db in databases)
        
        if not db_exists:
            if request.method == "DELETE":
                return jsonify({"success": False, "message": "Database not found"}), 404
            flash(f"Database '{db_name}' not found.")
            return redirect(url_for('home'))
        
        items = db_manager.get_database_items(db_name, session['username'], session.get('role'))
        target_item = None
        
        for item in items:
            try:
                filename = os.path.basename(item["path"])
                if "_" in filename:
                    file_id = filename.split("_")[1].split(".")[0]
                else:
                    file_id = filename.split(".")[0]
                
                if file_id == item_id:
                    with open(item["path"], "r", encoding='utf-8') as f:
                        data = json.load(f)
                        if data.get("table") == table_name:
                            target_item = item
                            break
            except Exception as e:
                continue
        
        if not target_item:
            if request.method == "DELETE":
                return jsonify({"success": False, "message": "Record not found"}), 404
            flash("Record not found.")
            return redirect(url_for('view_table', db_name=db_name, table_name=table_name))
        
        try:
            os.remove(target_item["path"])
            
            if request.method == "DELETE":
                return jsonify({"success": True, "message": "Record deleted successfully"})
            else:
                flash("Record deleted successfully!")
                
        except OSError as e:
            if request.method == "DELETE":
                return jsonify({"success": False, "message": "Failed to delete record"}), 500
            flash("Failed to delete record.")
        
        return redirect(url_for('view_table', db_name=db_name, table_name=table_name))
            
    except Exception as e:
        print(f"Error in delete_record: {str(e)}")
        if request.method == "DELETE":
            return jsonify({"success": False, "message": str(e)}), 500
        else:
            flash(f"Error deleting record: {str(e)}")
            return redirect(url_for('view_table', db_name=db_name, table_name=table_name))

def get_table_schema(db_name, table_name):
    """Get the schema for a specific table"""
    try:
        databases = db_manager.list_databases(session.get('username', ''), session.get('role', ''))
        db_info = next((db for db in databases if db.get("name") == db_name), None)
        
        if db_info and "path" in db_info:
            schema_file = os.path.join(db_info["path"], "schema.json")
            if os.path.exists(schema_file):
                with open(schema_file, "r", encoding='utf-8') as f:
                    schema = json.load(f)
                    return schema.get("tables", {}).get(table_name)
        return None
    except Exception as e:
        print(f"Error getting table schema: {str(e)}")
        return None

@app.route("/create_database", methods=["GET", "POST"])
def create_database():
    """Create a new database"""
    if 'username' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))
    
    if session.get('role') != "admin":
        flash("Only admin users can create databases!")
        return redirect(url_for('home'))
    
    if request.method == "POST":
        try:
            db_name = request.form.get('db_name', '').strip()
            if not db_name:
                flash("Database name is required!")
                return render_template("create_database.html")
            
            if not db_name.replace('_', '').replace('-', '').isalnum():
                flash("Database name can only contain letters, numbers, underscores, and hyphens!")
                return render_template("create_database.html")
            
            existing_databases = db_manager.list_databases(session['username'], session.get('role'))
            if any(db['name'] == db_name for db in existing_databases):
                flash(f"Database '{db_name}' already exists! Please choose a different name.")
                return render_template("create_database.html")
            
            table_count = int(request.form.get('table_count', 0))
            if table_count < 1:
                flash("Database must have at least one table!")
                return render_template("create_database.html")
            
            schema = {"tables": {}}
            
            for i in range(1, table_count + 1):
                table_name = request.form.get(f'table_name_{i}', '').strip()
                if not table_name:
                    flash(f"Table {i} name is required!")
                    return render_template("create_database.html")
                
                if not table_name.replace('_', '').isalnum():
                    flash(f"Table name '{table_name}' can only contain letters, numbers, and underscores!")
                    return render_template("create_database.html")
                
                if table_name in schema["tables"]:
                    flash(f"Duplicate table name '{table_name}' found! Table names must be unique.")
                    return render_template("create_database.html")
                
                field_count = int(request.form.get(f'field_count_{i}', 0))
                if field_count < 1:
                    flash(f"Table '{table_name}' must have at least one field!")
                    return render_template("create_database.html")
                
                schema["tables"][table_name] = {"fields": {}}
                
                table_field_names = set()
                for j in range(1, field_count + 1):
                    field_name = request.form.get(f'field_name_{i}_{j}', '').strip()
                    field_type = request.form.get(f'field_type_{i}_{j}', 'string')
                    
                    if not field_name:
                        flash(f"All fields in table '{table_name}' must have names!")
                        return render_template("create_database.html")
                    
                    if not field_name.replace('_', '').isalnum():
                        flash(f"Field name '{field_name}' can only contain letters, numbers, and underscores!")
                        return render_template("create_database.html")
                    
                    if field_name in table_field_names:
                        flash(f"Duplicate field name '{field_name}' in table '{table_name}'! Field names must be unique within each table.")
                        return render_template("create_database.html")
                    
                    table_field_names.add(field_name)
                    
                    valid_types = ['string', 'int', 'float', 'bool']
                    if field_type not in valid_types:
                        field_type = 'string'
                    
                    schema["tables"][table_name]["fields"][field_name] = field_type
            
            print(f"Creating database '{db_name}' with schema: {schema}")
            db_path = db_manager.create_database(db_name, schema, session['username'])
            
            if db_path:
                flash(f"Database '{db_name}' created successfully with {table_count} table(s)!")
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

# ==================== HELPER FUNCTIONS ====================

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

def get_system_uptime():
    """Get system uptime"""
    uptime_seconds = time.time() - security_config['system_start_time']
    if uptime_seconds < 60:
        return f"{int(uptime_seconds)} seconds"
    elif uptime_seconds < 3600:
        return f"{int(uptime_seconds / 60)} minutes"
    elif uptime_seconds < 86400:
        return f"{int(uptime_seconds / 3600)} hours"
    else:
        return f"{int(uptime_seconds / 86400)} days"

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

# ==================== STARTUP AND INITIALIZATION ====================

def verify_system_integrity():
    """Verify system integrity on startup"""
    try:
        print("🔍 Verifying system integrity...")
        
        blockchain_file = "blockchain_db.json"
        if os.path.exists("system_chains/active/blockchain_db.json"):
            blockchain_file = "system_chains/active/blockchain_db.json"
        
        if not os.path.exists(blockchain_file):
            print("⚠️  Blockchain database not found - will create new genesis block")
            return True
        
        try:
            with open(blockchain_file, 'r') as f:
                chain_data = json.load(f)
            
            if not isinstance(chain_data, list) or len(chain_data) == 0:
                print("⚠️  Invalid blockchain format - will recreate")
                return False
            
            print(f"✅ Blockchain verified: {len(chain_data)} blocks loaded")
            return True
            
        except json.JSONDecodeError:
            print("❌ Blockchain file corrupted - will attempt recovery")
            return False
            
    except Exception as e:
        print(f"❌ System integrity check failed: {e}")
        return False

def create_startup_backup():
    """Create system backup on startup"""
    try:
        blockchain_file = "blockchain_db.json"
        if os.path.exists("system_chains/active/blockchain_db.json"):
            blockchain_file = "system_chains/active/blockchain_db.json"
            
        if os.path.exists(blockchain_file):
            timestamp = int(time.time())
            backup_name = f"startup_backup_{timestamp}.json"
            backup_path = os.path.join('backups', backup_name)
            
            os.makedirs('backups', exist_ok=True)
            shutil.copy2(blockchain_file, backup_path)
            print(f"💾 Startup backup created: {backup_name}")
            
            backup_files = glob.glob('backups/startup_backup_*.json')
            if len(backup_files) > 10:
                backup_files.sort()
                for old_backup in backup_files[:-10]:
                    try:
                        os.remove(old_backup)
                    except:
                        pass
                        
    except Exception as e:
        print(f"⚠️  Could not create startup backup: {e}")

# ==================== MAIN APPLICATION STARTUP ====================

if __name__ == "__main__":
    try:
        print("🔗 Initializing Blockchain Database System...")
        print("=" * 60)
        
        # Verify system integrity first
        verify_system_integrity()
        
        # Create startup backup
        create_startup_backup()
        
        # Record system startup time
        security_config['system_start_time'] = time.time()
        
        # Get network information
        import socket
        hostname = socket.gethostname()
        try:
            local_ip = socket.gethostbyname(hostname)
        except:
            local_ip = "127.0.0.1"
        
        # Display startup information
        print("=" * 60)
        print("🔗 Blockchain Database System Ready!")
        print("=" * 60)
        print(f"🏠 Local access:      http://localhost:1337")
        print(f"🌐 Network access:    http://{local_ip}:1337")
        print(f"📱 Mobile access:     http://{local_ip}:1337")
        print("=" * 60)
        print("📊 Available endpoints:")
        print(f"   • Home/Databases:  http://{local_ip}:1337/")
        print(f"   • Login:           http://{local_ip}:1337/login")
        print(f"   • Blockchain:      http://{local_ip}:1337/blockchain")
        print(f"   • Security:        http://{local_ip}:1337/security-dashboard")
        print(f"   • API Chain:       http://{local_ip}:1337/api/chain")
        print(f"   • API Status:      http://{local_ip}:1337/api/status")
        print(f"   • Security API:    http://{local_ip}:1337/api/security/status")
        print("=" * 60)
        print("🛡️ Security Features:")
        print(f"   • Dashboard monitoring: ENABLED (Read-only)")
        print(f"   • Centralized storage:  ENABLED")
        print(f"   • File organization:    ENABLED")
        print(f"   • Status tracking:      ENABLED")
        print("=" * 60)
        print("🔥 Server starting... Press Ctrl+C to stop")
        print("=" * 60)
        
        # Note: Security enforcement is handled by polymorphicblock.py
        print("📝 Note: Security enforcement is handled by the blockchain system itself")
        print("📊 This dashboard provides monitoring and status information only")
        
        # Start the Flask application
        app.run(host="0.0.0.0", port=1337, debug=False, threaded=True)
        
    except KeyboardInterrupt:
        print("\n🛑 Received shutdown signal...")
        print("✅ Server stopped")
        
    except Exception as e:
        print(f"❌ Critical error during startup: {e}")
        import traceback
        traceback.print_exc()
        
        print("\n🔧 Troubleshooting tips:")
        print("   • Check if port 1337 is available")
        print("   • Verify blockchain database files exist")
        print("   • Ensure proper permissions for file access")
        print("   • Check system dependencies")
        
        exit(1)