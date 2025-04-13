from flask import Flask, render_template, request, redirect, jsonify
import json
import time
import sys
import os

# Import from blockchain_databases correctly - using DatabaseManager
from blockchain_databases import DatabaseManager

# Initialize the blockchain system first
if not os.path.exists("blockchain_db.json"):
    from blockRunner import initialize_blockchain_system
    auth_system, blockchain, refresher = initialize_blockchain_system()
else:
    from blockRunner import auth_system, blockchain, refresher
    # If the system wasn't initialized before importing, initialize now
    if blockchain is None or refresher is None:
        from blockRunner import initialize_blockchain_system
        auth_system, blockchain, refresher = initialize_blockchain_system()

from polymorphicblock import Block

app = Flask(__name__)

# Create database manager instance using the auth_system
db_manager = DatabaseManager(auth_system)

# login page
@app.route('/login', methods=['GET', 'POST'], endpoint='login')
def login():
    return render_template('login.html')

# logout route
# to be added here

# Database GUI routes
@app.route("/")
def home():
    databases = db_manager.list_databases()
    return render_template("home.html", databases=databases)

@app.route("/tables/<db_name>")
def list_tables(db_name):
    tables = db_manager.list_tables(db_name) if hasattr(db_manager, 'list_tables') else []
    return render_template("tables.html", db_name=db_name, tables=tables)

@app.route("/table/<db_name>/<table_name>")
def view_table(db_name, table_name):
    rows = db_manager.get_database_items(db_name) if hasattr(db_manager, 'get_database_items') else []
    return render_template("table_view.html", db_name=db_name, table_name=table_name, rows=rows)

@app.route("/delete/<db>/<table>/<int:rowid>")
def delete_row(db, table, rowid):
    # Check if method exists before calling
    if hasattr(db_manager, 'delete_record_by_id'):
        db_manager.delete_record_by_id(db, table, rowid)
    return redirect(f"/table/{db}/{table}")

# Blockchain API routes
@app.route("/api/chain", methods=["GET"])
def get_chain():
    """Return the entire blockchain"""
    return jsonify(blockchain.to_dict()), 200

@app.route("/api/add", methods=["POST"])
def add_block():
    """Add a new block to the blockchain"""
    try:
        data = request.json.get("data")
        if not data:
            return jsonify({"error": "Missing data"}), 400

        # Create and add new block
        new_block = Block(len(blockchain.chain), time.time(), data, "")
        blockchain.add_block(new_block)
        
        # Refresh the blockchain state
        refresher.refresh()
        
        return jsonify({"message": "Block added", "block": new_block.to_dict()}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/refresh", methods=["POST"])
def trigger_refresh():
    """Manually trigger a blockchain refresh"""
    try:
        refresher.refresh()
        return jsonify({"message": "Refreshed core state", "status": "success"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/status", methods=["GET"])
def get_status():
    """Get the blockchain system status"""
    try:
        is_valid = blockchain.is_chain_valid()
        return jsonify({
            "status": "healthy" if is_valid else "corrupted",
            "chain_length": len(blockchain.chain),
            "latest_block": blockchain.get_latest_block().to_dict() if blockchain.chain else None
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Blockchain visualization dashboard
@app.route("/blockchain")
def blockchain_dashboard():
    return render_template("blockchain_dashboard.html")

# Database management routes - these might need to be adjusted based on your actual DB methods
@app.route("/databases")
def list_all_databases():
    """List all databases in the system"""
    databases = db_manager.list_databases()
    return jsonify(databases), 200

@app.route("/database_items/<db_name>", methods=["GET"])
def get_database_items(db_name):
    """Get all items in a specific database"""
    items = db_manager.get_database_items(db_name)
    return jsonify(items), 200

if __name__ == "__main__":
    print("Starting combined server on port 1337...")
    print("DB GUI available at: http://localhost:1337/")
    print("Blockchain dashboard: http://localhost:1337/blockchain") # it should really serve here not on just the port
    print("Blockchain API endpoints:")
    print("  GET  /api/chain   - Get the entire blockchain")
    print("  POST /api/add     - Add a new block (requires JSON data)")
    print("  POST /api/refresh - Trigger system refresh")
    print("  GET  /api/status  - Get blockchain system status")
    app.run(host="0.0.0.0", port=1337, debug=True)