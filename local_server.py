from flask import Flask, request, jsonify
import json
import time
import sys
import os

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

@app.route("/chain", methods=["GET"])
def get_chain():
    """Return the entire blockchain"""
    return jsonify(blockchain.to_dict()), 200

@app.route("/add", methods=["POST"])
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

@app.route("/refresh", methods=["POST"])
def trigger_refresh():
    """Manually trigger a blockchain refresh"""
    try:
        refresher.refresh()
        return jsonify({"message": "Refreshed core state", "status": "success"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/status", methods=["GET"])
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

if __name__ == "__main__":
    print("Starting blockchain local server on port 133766...")
    print("Available endpoints:")
    print("  GET  /chain   - Get the entire blockchain")
    print("  POST /add     - Add a new block (requires JSON data)")
    print("  POST /refresh - Trigger system refresh")
    print("  GET  /status  - Get blockchain system status")
    app.run(host="0.0.0.0", port=133766, debug=True)