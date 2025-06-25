# db_gui.py - Complete Enhanced Version with Integrated Security Dashboard
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
from polymorphicblock import AuthSystem, ChainDirectoryManager
from centralized_chain_management import ChainDirectoryManager as CentralizedManager


app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize authentication and database systems
auth_system = AuthSystem()
db_storage = DatabaseStorage()
db_manager = DatabaseManager(auth_system)
blockchain = auth_system.blockchain

# Use the centralized chain manager from the blockchain
chain_manager = blockchain.chain_manager if hasattr(blockchain, 'chain_manager') else ChainDirectoryManager()

# Security tracking and configuration
security_violations = []
quarantined_blocks = []
security_config = {
    'enable_auto_reorder': False,
    'trigger_threshold': 5,
    'randomness_factor': 0.7,
    'scan_interval': 3600,
    'auto_quarantine': False,
    'system_start_time': time.time(),
    'reorder_count': 0,
    'data_recovery_count': 0,
    'last_security_scan': None
}

# ==================== SECURITY ANALYZER CLASS ====================
class SecurityAnalyzer:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.violation_history = []
        self.quarantined_blocks = []
        self.security_events = []
        self.load_security_data()
    
    def load_security_data(self):
        """Load existing security data from files"""
        try:
            # Load quarantined blocks
            quarantine_file = 'quarantined_blocks.json'
            if os.path.exists(quarantine_file):
                with open(quarantine_file, 'r') as f:
                    self.quarantined_blocks = json.load(f)
            
            # Load security timeline
            timeline_file = 'security_timeline.json'
            if os.path.exists(timeline_file):
                with open(timeline_file, 'r') as f:
                    self.security_events = json.load(f)
        except Exception as e:
            print(f"Error loading security data: {e}")
    
    def comprehensive_security_scan(self):
        """Perform comprehensive security analysis"""
        violations = []
        current_time = time.time()
        
        # Analyze each block for various security issues
        for i, block in enumerate(self.blockchain.chain):
            try:
                # 1. Hash Integrity Check
                if hasattr(block, 'hash') and hasattr(block, 'calculate_hash'):
                    calculated_hash = block.calculate_hash()
                    if block.hash != calculated_hash:
                        violations.append({
                            'block_id': getattr(block, 'index', i),
                            'violation_type': 'HASH_MISMATCH',
                            'severity': 'CRITICAL',
                            'timestamp': current_time,
                            'description': f'Block hash validation failed',
                            'stored_hash': block.hash,
                            'calculated_hash': calculated_hash,
                            'affected_data': str(block.data)[:100] + '...' if len(str(block.data)) > 100 else str(block.data)
                        })
                
                # 2. Chain Continuity Check
                if i > 0:
                    previous_block = self.blockchain.chain[i-1]
                    if (hasattr(block, 'previous_hash') and hasattr(previous_block, 'hash') and
                        block.previous_hash != previous_block.hash):
                        violations.append({
                            'block_id': getattr(block, 'index', i),
                            'violation_type': 'CHAIN_BREAK',
                            'severity': 'CRITICAL',
                            'timestamp': current_time,
                            'description': f'Chain integrity violation between blocks {i-1} and {i}',
                            'expected_hash': previous_block.hash,
                            'actual_hash': block.previous_hash
                        })
                
                # 3. Data Structure Validation
                if hasattr(block, 'data'):
                    if not isinstance(block.data, dict):
                        violations.append({
                            'block_id': getattr(block, 'index', i),
                            'violation_type': 'DATA_STRUCTURE_INVALID',
                            'severity': 'HIGH',
                            'timestamp': current_time,
                            'description': 'Block data is not a valid dictionary structure'
                        })
                    elif not block.data.get('action'):
                        violations.append({
                            'block_id': getattr(block, 'index', i),
                            'violation_type': 'MISSING_ACTION',
                            'severity': 'MEDIUM',
                            'timestamp': current_time,
                            'description': 'Block missing required action field'
                        })
                
                # 4. Timestamp Validation
                if i > 0 and hasattr(block, 'timestamp') and hasattr(previous_block, 'timestamp'):
                    if block.timestamp < previous_block.timestamp:
                        violations.append({
                            'block_id': getattr(block, 'index', i),
                            'violation_type': 'TIMESTAMP_VIOLATION',
                            'severity': 'HIGH',
                            'timestamp': current_time,
                            'description': 'Block timestamp is earlier than previous block'
                        })
                
                # 5. Authentication Pattern Analysis
                if hasattr(block, 'data') and isinstance(block.data, dict):
                    if block.data.get('action') == 'authenticate':
                        # Check for rapid authentication attempts (potential brute force)
                        recent_auths = self._count_recent_authentications(block.data.get('username', ''), current_time)
                        if recent_auths > 10:  # More than 10 auth attempts in recent period
                            violations.append({
                                'block_id': getattr(block, 'index', i),
                                'violation_type': 'SUSPICIOUS_AUTH_PATTERN',
                                'severity': 'HIGH',
                                'timestamp': current_time,
                                'description': f'Suspicious authentication pattern detected for user {block.data.get("username", "unknown")}'
                            })
                
                # 6. Database Operation Security Check
                if hasattr(block, 'data') and isinstance(block.data, dict):
                    if block.data.get('action') in ['create_database', 'store_item']:
                        # Check for unauthorized database operations
                        if not self._validate_database_permission(block.data):
                            violations.append({
                                'block_id': getattr(block, 'index', i),
                                'violation_type': 'UNAUTHORIZED_DB_OPERATION',
                                'severity': 'HIGH',
                                'timestamp': current_time,
                                'description': f'Potentially unauthorized database operation by {block.data.get("username", "unknown")}'
                            })
                
            except Exception as e:
                violations.append({
                    'block_id': getattr(block, 'index', i),
                    'violation_type': 'ANALYSIS_ERROR',
                    'severity': 'MEDIUM',
                    'timestamp': current_time,
                    'description': f'Error analyzing block: {str(e)}'
                })
        
        # Store violation history
        self.violation_history.extend(violations)
        
        return {
            'violations': violations,
            'scan_timestamp': current_time,
            'blocks_analyzed': len(self.blockchain.chain),
            'total_violations': len(violations)
        }
    
    def _count_recent_authentications(self, username, current_time, window_seconds=300):
        """Count authentication attempts for a user in recent time window"""
        count = 0
        for block in self.blockchain.chain:
            if (hasattr(block, 'data') and isinstance(block.data, dict) and
                block.data.get('action') == 'authenticate' and
                block.data.get('username') == username and
                hasattr(block, 'timestamp') and
                current_time - block.timestamp <= window_seconds):
                count += 1
        return count
    
    def _validate_database_permission(self, block_data):
        """Validate if database operation is authorized"""
        # Simple validation - you can enhance this based on your permission model
        username = block_data.get('username', '')
        action = block_data.get('action', '')
        
        # Check if user exists in the system
        for block in self.blockchain.chain:
            if (hasattr(block, 'data') and isinstance(block.data, dict) and
                block.data.get('action') == 'register' and
                block.data.get('username') == username):
                user_role = block.data.get('role', 'user')
                # Only admins can create databases
                if action == 'create_database' and user_role != 'admin':
                    return False
                return True
        
        return False  # User not found
    
    def quarantine_block(self, block_id, reason="Security violation detected"):
        """Quarantine a specific block"""
        try:
            # Find the block
            target_block = None
            for block in self.blockchain.chain:
                if getattr(block, 'index', None) == block_id:
                    target_block = block
                    break
            
            if not target_block:
                return False
            
            # Create quarantine record
            quarantine_record = {
                'block_id': block_id,
                'quarantine_timestamp': time.time(),
                'reason': reason,
                'block_data': target_block.to_dict() if hasattr(target_block, 'to_dict') else str(target_block),
                'quarantined_by': 'system'
            }
            
            self.quarantined_blocks.append(quarantine_record)
            
            # Save quarantine data
            with open('quarantined_blocks.json', 'w') as f:
                json.dump(self.quarantined_blocks, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error quarantining block {block_id}: {e}")
            return False
    
    def restore_block(self, block_id):
        """Restore a quarantined block"""
        try:
            # Find and remove from quarantine
            for i, record in enumerate(self.quarantined_blocks):
                if record['block_id'] == block_id:
                    restored_record = self.quarantined_blocks.pop(i)
                    
                    # Save updated quarantine data
                    with open('quarantined_blocks.json', 'w') as f:
                        json.dump(self.quarantined_blocks, f, indent=2)
                    
                    return True
            
            return False
            
        except Exception as e:
            print(f"Error restoring block {block_id}: {e}")
            return False

# ==================== SECURITY MONITOR CLASS ====================
class SecurityMonitor:
    def __init__(self, blockchain, security_analyzer):
        self.blockchain = blockchain
        self.security_analyzer = security_analyzer
        self.monitoring = False
        self.monitor_thread = None
        self.violation_threshold = 5
        self.auto_remediation_enabled = False
    
    def start_monitoring(self):
        """Start continuous security monitoring"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            print("🛡️ Security monitoring started")
    
    def stop_monitoring(self):
        """Stop security monitoring"""
        self.monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        print("🛡️ Security monitoring stopped")
    
    def _monitor_loop(self):
        """Continuous monitoring loop"""
        while self.monitoring:
            try:
                # Perform security scan
                scan_results = self.security_analyzer.comprehensive_security_scan()
                
                # Check if violations exceed threshold
                if len(scan_results['violations']) >= self.violation_threshold:
                    self._handle_security_breach(scan_results)
                
                # Wait before next scan
                time.sleep(30)  # Scan every 30 seconds
                
            except Exception as e:
                print(f"Error in security monitoring: {e}")
                time.sleep(60)  # Wait longer on error
    
    def _handle_security_breach(self, scan_results):
        """Handle detected security breach"""
        print(f"🚨 SECURITY BREACH DETECTED: {len(scan_results['violations'])} violations found")
        
        # Log security event
        log_security_event('security_breach', 'detected', {
            'violation_count': len(scan_results['violations']),
            'auto_remediation': self.auto_remediation_enabled
        })
        
        if self.auto_remediation_enabled:
            self._perform_auto_remediation(scan_results)
    
    def _perform_auto_remediation(self, scan_results):
        """Perform automatic remediation"""
        try:
            # Quarantine critical violations
            critical_violations = [v for v in scan_results['violations'] if v['severity'] == 'CRITICAL']
            
            for violation in critical_violations:
                self.security_analyzer.quarantine_block(
                    violation['block_id'], 
                    f"Auto-quarantine: {violation['violation_type']}"
                )
            
            # Trigger chain validation and repair
            if len(critical_violations) > 0:
                self.blockchain.is_chain_valid()  # This will trigger fallback response
            
            print(f"🛠️ Auto-remediation completed: {len(critical_violations)} blocks quarantined")
            
        except Exception as e:
            print(f"Error in auto-remediation: {e}")

# Initialize global security components
security_analyzer = None
security_monitor = None

def initialize_security_system():
    """Initialize the security system components"""
    global security_analyzer, security_monitor
    
    try:
        security_analyzer = SecurityAnalyzer(blockchain)
        security_monitor = SecurityMonitor(blockchain, security_analyzer)
        
        # Start monitoring if auto-remediation is enabled
        if security_config.get('enable_auto_reorder', False):
            security_monitor.auto_remediation_enabled = True
            security_monitor.start_monitoring()
        
        print("🛡️ Security system initialized successfully")
        
    except Exception as e:
        print(f"❌ Failed to initialize security system: {e}")

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
        username, role = auth_system.authenticate(username, password)
        
        if username:
            session['username'] = username
            session['role'] = role
            flash(f"Welcome, {username}!")
            
            # Log successful authentication
            log_security_event('authentication', 'success', {
                'username': username,
                'role': role,
                'ip_address': request.remote_addr
            })
            
            return redirect(url_for('home'))
        else:
            # Log failed authentication
            log_security_event('authentication', 'failed', {
                'attempted_username': username,
                'ip_address': request.remote_addr
            })
            flash("Authentication failed. Please check your credentials.")
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    """Log out user"""
    username = session.get('username')
    
    # Log logout
    if username:
        log_security_event('logout', 'success', {
            'username': username,
            'ip_address': request.remote_addr
        })
    
    session.pop('username', None)
    session.pop('role', None)
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route("/blockchain")
def blockchain_dashboard():
    """Enhanced blockchain dashboard with advanced features"""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("blockchain_dashboard.html")

@app.route("/security-dashboard")
def security_dashboard():
    """Main security dashboard"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Only admin users can access security dashboard
    if session.get('role') != 'admin':
        flash("Access denied. Admin privileges required.")
        return redirect(url_for('home'))
    
    return render_template("security_violations.html")

# ==================== INTEGRATED SECURITY ANALYZER ====================
class IntegratedSecurityAnalyzer:
    def __init__(self, blockchain, chain_manager):
        self.blockchain = blockchain
        self.chain_manager = chain_manager
        self.violation_history = []
        self.quarantined_blocks = []
        self.security_events = []
        self.load_security_data()
    
    def load_security_data(self):
        """Load existing security data from centralized locations"""
        try:
            # Load quarantined blocks from centralized quarantine directory
            quarantine_dir = self.chain_manager.subdirs['quarantine']
            quarantine_files = list(quarantine_dir.glob('quarantined_blocks_*.json'))
            
            self.quarantined_blocks = []
            for file_path in quarantine_files:
                try:
                    with open(file_path, 'r') as f:
                        quarantine_data = json.load(f)
                        if 'quarantined_block_data' in quarantine_data:
                            self.quarantined_blocks.extend(quarantine_data['quarantined_block_data'])
                        elif 'infected_blocks' in quarantine_data:
                            self.quarantined_blocks.extend(quarantine_data['infected_blocks'])
                except Exception as e:
                    print(f"Error loading quarantine file {file_path}: {e}")
            
            # Load security timeline from forensics directory
            forensics_dir = self.chain_manager.subdirs['forensics']
            forensics_files = list(forensics_dir.glob('forensic_report_*.json'))
            
            self.security_events = []
            for file_path in forensics_files:
                try:
                    with open(file_path, 'r') as f:
                        forensic_data = json.load(f)
                        event = {
                            'type': 'forensic_analysis',
                            'timestamp': forensic_data.get('forensic_timestamp', time.time()),
                            'title': 'Security Analysis Completed',
                            'description': f"Analysis type: {forensic_data.get('analysis_type', 'Unknown')}",
                            'details': forensic_data
                        }
                        self.security_events.append(event)
                except Exception as e:
                    print(f"Error loading forensic file {file_path}: {e}")
            
            print(f"🔍 [SECURITY] Loaded {len(self.quarantined_blocks)} quarantined blocks")
            print(f"📊 [SECURITY] Loaded {len(self.security_events)} security events")
            
        except Exception as e:
            print(f"Error loading security data: {e}")
    
    def comprehensive_security_scan(self):
        """Perform comprehensive security analysis using blockchain's built-in methods"""
        violations = []
        current_time = time.time()
        
        print(f"\n🔍 [SECURITY SCAN] Analyzing {len(self.blockchain.chain)} blocks...")
        
        # Use the blockchain's validation method which already detects infections
        try:
            # This will trigger the enhanced validation in polymorphicblock.py
            is_valid = self.blockchain.is_chain_valid()
            
            if not is_valid:
                print("🚨 [SECURITY] Chain validation failed - checking for new quarantine data")
                # Reload quarantine data after validation
                self.load_security_data()
        except Exception as e:
            print(f"Error during chain validation: {e}")
        
        # Analyze each block for additional security issues
        for i in range(1, len(self.blockchain.chain)):
            current_block = self.blockchain.chain[i]
            previous_block = self.blockchain.chain[i-1]
            
            try:
                # 1. Hash Integrity Check
                calculated_hash = current_block.calculate_hash()
                if current_block.hash != calculated_hash:
                    violations.append({
                        'block_id': current_block.index,
                        'violation_type': 'HASH_MISMATCH',
                        'severity': 'CRITICAL',
                        'timestamp': current_time,
                        'description': f'Block hash validation failed',
                        'stored_hash': current_block.hash,
                        'calculated_hash': calculated_hash,
                        'affected_data': str(current_block.data)[:100] + '...' if len(str(current_block.data)) > 100 else str(current_block.data)
                    })
                
                # 2. Chain Continuity Check
                if current_block.previous_hash != previous_block.hash:
                    violations.append({
                        'block_id': current_block.index,
                        'violation_type': 'CHAIN_BREAK',
                        'severity': 'CRITICAL',
                        'timestamp': current_time,
                        'description': f'Chain integrity violation between blocks {i-1} and {i}',
                        'expected_hash': previous_block.hash,
                        'actual_hash': current_block.previous_hash
                    })
                
                # 3. Timestamp Validation
                #if i > 0 and current_block.timestamp < previous_block.timestamp:
                 #   violations.append({
                  #      'block_id': current_block.index,
                   #     'violation_type': 'TIMESTAMP_ANOMALY',
                    #    'severity': 'WARNING',
                     #   'timestamp': current_time,
                      #  'description': 'Block timestamp is earlier than previous block',
                       # 'current_timestamp': current_block.timestamp,
                        #'previous_timestamp': previous_block.timestamp
                    #})
                
                # 4. Data Structure Validation
                if not isinstance(current_block.data, dict):
                    violations.append({
                        'block_id': current_block.index,
                        'violation_type': 'DATA_CORRUPTION',
                        'severity': 'HIGH',
                        'timestamp': current_time,
                        'description': 'Block data is not a valid dictionary structure'
                    })
                elif not current_block.data.get('action'):
                    violations.append({
                        'block_id': current_block.index,
                        'violation_type': 'MISSING_ACTION',
                        'severity': 'MEDIUM',
                        'timestamp': current_time,
                        'description': 'Block missing required action field'
                    })
                
            except Exception as e:
                violations.append({
                    'block_id': getattr(current_block, 'index', i),
                    'violation_type': 'ANALYSIS_ERROR',
                    'severity': 'MEDIUM',
                    'timestamp': current_time,
                    'description': f'Error analyzing block: {str(e)}'
                })
        
        # Store violation history
        self.violation_history.extend(violations)
        
        return {
            'violations': violations,
            'scan_timestamp': current_time,
            'blocks_analyzed': len(self.blockchain.chain),
            'total_violations': len(violations)
        }
    
    def get_quarantine_data(self):
        """Get quarantined blocks data from centralized storage"""
        return self.quarantined_blocks
    
    def get_security_timeline(self):
        """Get security event timeline from centralized storage"""
        timeline = self.security_events.copy()
        
        # Add recent violations to timeline
        for violation in self.violation_history[-10:]:
            timeline.append({
                'type': 'violation_detected',
                'timestamp': violation['timestamp'],
                'title': f"Security Violation: {violation['violation_type']}",
                'description': f"Block #{violation['block_id']}: {violation['description']}",
                'severity': violation['severity']
            })
        
        # Sort by timestamp (newest first)
        timeline.sort(key=lambda x: x['timestamp'], reverse=True)
        return timeline[:100]

# ==================== INTEGRATED SECURITY MONITOR ====================
class IntegratedSecurityMonitor:
    def __init__(self, blockchain, security_analyzer):
        self.blockchain = blockchain
        self.security_analyzer = security_analyzer
        self.monitoring = False
        self.monitor_thread = None
        self.violation_threshold = 5
        self.auto_remediation_enabled = False
    
    def start_monitoring(self):
        """Start continuous security monitoring"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            print("🛡️ Security monitoring started")
    
    def stop_monitoring(self):
        """Stop security monitoring"""
        self.monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        print("🛡️ Security monitoring stopped")
    
    def _monitor_loop(self):
        """Continuous monitoring loop"""
        while self.monitoring:
            try:
                # Perform security scan
                scan_results = self.security_analyzer.comprehensive_security_scan()
                
                # Check if violations exceed threshold
                if len(scan_results['violations']) >= self.violation_threshold:
                    self._handle_security_breach(scan_results)
                
                # Wait before next scan
                time.sleep(30)  # Scan every 30 seconds
                
            except Exception as e:
                print(f"Error in security monitoring: {e}")
                time.sleep(60)  # Wait longer on error
    
    def _handle_security_breach(self, scan_results):
        """Handle detected security breach"""
        print(f"🚨 SECURITY BREACH DETECTED: {len(scan_results['violations'])} violations found")
        
        # Log security event
        log_security_event('security_breach', 'detected', {
            'violation_count': len(scan_results['violations']),
            'auto_remediation': self.auto_remediation_enabled
        })
        
        if self.auto_remediation_enabled:
            self._perform_auto_remediation(scan_results)
    
    def _perform_auto_remediation(self, scan_results):
        """Perform automatic remediation using blockchain's built-in methods"""
        try:
            print("🛠️ [AUTO-REMEDIATION] Starting automatic remediation...")
            
            # Trigger blockchain validation which will handle quarantine automatically
            self.blockchain.is_chain_valid()
            
            # Reload security data
            self.security_analyzer.load_security_data()
            
            print(f"🛠️ Auto-remediation completed")
            
        except Exception as e:
            print(f"Error in auto-remediation: {e}")

# Initialize integrated security components
security_analyzer = None
security_monitor = None

def initialize_integrated_security_system():
    """Initialize the integrated security system components"""
    global security_analyzer, security_monitor
    
    try:
        security_analyzer = IntegratedSecurityAnalyzer(blockchain, chain_manager)
        security_monitor = IntegratedSecurityMonitor(blockchain, security_analyzer)
        
        # Start monitoring if auto-remediation is enabled
        if security_config.get('enable_auto_reorder', False):
            security_monitor.auto_remediation_enabled = True
            security_monitor.start_monitoring()
        
        print("🛡️ Integrated security system initialized successfully")
        
    except Exception as e:
        print(f"❌ Failed to initialize integrated security system: {e}")

# ==================== ENHANCED SECURITY API ENDPOINTS ====================

@app.route("/api/security/status", methods=["GET"])
def get_security_status():
    """Get comprehensive security status using integrated system"""
    try:
        global security_analyzer
        
        if not security_analyzer:
            initialize_integrated_security_system()
        
        # Perform real-time security analysis
        violations = security_analyzer.comprehensive_security_scan()['violations']
        quarantine_data = security_analyzer.get_quarantine_data()
        
        # Calculate metrics
        integrity_score = 100
        critical_violations = len([v for v in violations if v['severity'] == 'CRITICAL'])
        high_violations = len([v for v in violations if v['severity'] == 'HIGH'])
        
        if len(blockchain.chain) > 0:
            integrity_score -= (critical_violations * 25)
            integrity_score -= (high_violations * 15)
            integrity_score = max(0, integrity_score)
        
        # Assess threat level
        threat_level = 'NONE'
        if critical_violations >= 3:
            threat_level = 'CRITICAL'
        elif critical_violations >= 1 or high_violations >= 5:
            threat_level = 'HIGH'
        elif high_violations >= 2:
            threat_level = 'MEDIUM'
        elif len(violations) > 0:
            threat_level = 'LOW'
        
        # Calculate system status
        system_status = 'healthy'
        if critical_violations > 0:
            system_status = 'critical'
        elif high_violations >= 3:
            system_status = 'warning'
        elif len(violations) > 0:
            system_status = 'attention_needed'
        
        status = {
            'total_violations': len(violations),
            'quarantined_blocks': len(quarantine_data),
            'integrity_score': integrity_score,
            'threat_level': threat_level,
            'system_status': system_status,
            'last_security_scan': security_config.get('last_security_scan'),
            'data_recovery_count': security_config.get('data_recovery_count', 0),
            'auto_remediation_active': security_config.get('enable_auto_reorder', False),
            'monitoring_status': security_monitor.monitoring if security_monitor else False,
            'reorder_count': security_config.get('reorder_count', 0),
            'chain_length': len(blockchain.chain),
            'scan_interval': security_config.get('scan_interval', 3600),
            'centralized_storage': str(chain_manager.base_dir),
            'violation_breakdown': {
                'critical': critical_violations,
                'high': high_violations,
                'medium': len([v for v in violations if v['severity'] == 'MEDIUM']),
                'low': len([v for v in violations if v['severity'] == 'LOW'])
            },
            'last_update': time.time()
        }
        
        return jsonify(status), 200
        
    except Exception as e:
        print(f"Error getting security status: {e}")
        return jsonify({
            "error": str(e),
            "status": "error",
            "timestamp": time.time()
        }), 500

@app.route("/api/security/violations", methods=["GET"])
def get_security_violations():
    """Get detailed security violations from integrated system"""
    try:
        global security_analyzer
        
        if not security_analyzer:
            initialize_integrated_security_system()
        
        violations = security_analyzer.comprehensive_security_scan()['violations']
        
        # Sort violations by severity and timestamp
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        violations.sort(key=lambda x: (severity_order.get(x['severity'], 4), -x['timestamp']))
        
        # Group violations by type for analysis
        violation_types = defaultdict(int)
        for violation in violations:
            violation_types[violation['violation_type']] += 1
        
        return jsonify({
            'violations': violations,
            'total_count': len(violations),
            'critical_count': len([v for v in violations if v['severity'] == 'CRITICAL']),
            'high_count': len([v for v in violations if v['severity'] == 'HIGH']),
            'medium_count': len([v for v in violations if v['severity'] == 'MEDIUM']),
            'low_count': len([v for v in violations if v['severity'] == 'LOW']),
            'violation_types': dict(violation_types),
            'scan_timestamp': time.time(),
            'centralized_storage': str(chain_manager.base_dir),
            'recommendations': generate_security_recommendations(violations)
        }), 200
        
    except Exception as e:
        print(f"Error getting security violations: {e}")
        return jsonify({
            "error": str(e),
            "violations": [],
            "total_count": 0
        }), 500

@app.route("/api/security/quarantine", methods=["GET"])
def get_quarantine_status():
    """Get quarantined blocks status from centralized storage"""
    try:
        global security_analyzer
        
        if not security_analyzer:
            initialize_integrated_security_system()
        
        quarantine_data = security_analyzer.get_quarantine_data()
        
        # Add additional metadata to quarantine data
        enhanced_quarantine_data = []
        for item in quarantine_data:
            enhanced_item = item.copy()
            quarantine_time = item.get('quarantine_timestamp', item.get('timestamp', time.time()))
            enhanced_item['quarantine_duration'] = time.time() - quarantine_time
            enhanced_item['can_restore'] = True
            enhanced_item['storage_location'] = str(chain_manager.subdirs['quarantine'])
            enhanced_quarantine_data.append(enhanced_item)
        
        # Get quarantine directory info
        quarantine_dir = chain_manager.subdirs['quarantine']
        quarantine_files = list(quarantine_dir.glob('quarantined_blocks_*.json'))
        
        return jsonify({
            'infected_blocks': enhanced_quarantine_data,
            'total_count': len(quarantine_data),
            'quarantine_files': len(quarantine_files),
            'centralized_storage': str(quarantine_dir),
            'quarantine_summary': {
                'oldest_quarantine': min([item.get('quarantine_timestamp', item.get('timestamp', time.time()))
                                        for item in quarantine_data], default=time.time()),
                'newest_quarantine': max([item.get('quarantine_timestamp', item.get('timestamp', 0))
                                        for item in quarantine_data], default=0),
                'auto_quarantined': len([item for item in quarantine_data 
                                       if 'Auto-quarantine' in str(item.get('reason', ''))]),
                'manual_quarantined': len([item for item in quarantine_data 
                                         if 'Auto-quarantine' not in str(item.get('reason', ''))])
            }
        }), 200
        
    except Exception as e:
        print(f"Error getting quarantine status: {e}")
        return jsonify({
            "error": str(e),
            "infected_blocks": []
        }), 500

@app.route("/api/security/timeline", methods=["GET"])
def get_security_timeline():
    """Get security event timeline from centralized storage"""
    try:
        global security_analyzer
        
        if not security_analyzer:
            initialize_integrated_security_system()
        
        timeline = security_analyzer.get_security_timeline()
        
        return jsonify({
            'events': timeline,
            'total_events': len(timeline),
            'event_types': list(set([event.get('type', 'unknown') for event in timeline])),
            'centralized_storage': str(chain_manager.subdirs['forensics']),
            'last_update': time.time()
        }), 200
        
    except Exception as e:
        print(f"Error getting security timeline: {e}")
        return jsonify({
            "error": str(e),
            "events": []
        }), 500

@app.route("/api/security/scan", methods=["POST"])
def trigger_security_scan():
    """Trigger comprehensive security scan using integrated system"""
    try:
        if 'username' not in session or session.get('role') != 'admin':
            return jsonify({"error": "Unauthorized - Admin access required"}), 403
        
        global security_analyzer
        
        if not security_analyzer:
            initialize_integrated_security_system()
        
        # Perform comprehensive security scan
        scan_results = security_analyzer.comprehensive_security_scan()
        
        # Update last scan time
        security_config['last_security_scan'] = time.time()
        save_security_config()
        
        # Log security scan
        log_security_event('security_scan', 'completed', {
            'triggered_by': session['username'],
            'violations_found': len(scan_results.get('violations', [])),
            'blocks_analyzed': scan_results.get('blocks_analyzed', 0),
            'centralized_storage': str(chain_manager.base_dir),
            'scan_duration': time.time() - scan_results.get('scan_timestamp', time.time())
        })
        
        return jsonify({
            'status': 'completed',
            'results': {
                'violations': scan_results['violations'],
                'quarantined': security_analyzer.get_quarantine_data(),
                'centralized_storage': str(chain_manager.base_dir),
                'scan_details': scan_results
            },
            'scan_timestamp': time.time(),
            'triggered_by': session['username']
        }), 200
        
    except Exception as e:
        print(f"Error triggering security scan: {e}")
        return jsonify({
            "error": str(e),
            "status": "failed"
        }), 500

@app.route("/api/security/reorder", methods=["POST"])
def trigger_chain_reorder():
    """Trigger blockchain reorder for security"""
    try:
        if 'username' not in session or session.get('role') != 'admin':
            return jsonify({"error": "Unauthorized - Admin access required"}), 403
        
        # Get optional parameters
        request_data = request.get_json() or {}
        force_reorder = request_data.get('force', False)
        
        # Perform chain reorder
        reorder_results = perform_chain_reorder()
        
        # Log reorder action
        log_security_event('chain_reorder', 'triggered', {
            'triggered_by': session['username'],
            'blocks_affected': reorder_results.get('blocks_affected', 0),
            'randomness_factor': security_config.get('randomness_factor', 0.7),
            'force_reorder': force_reorder,
            'original_length': reorder_results.get('original_length', 0),
            'new_length': reorder_results.get('new_length', 0)
        })
        
        return jsonify({
            'status': 'completed',
            'results': reorder_results,
            'triggered_by': session['username'],
            'timestamp': time.time()
        }), 200
        
    except Exception as e:
        print(f"Error triggering chain reorder: {e}")
        return jsonify({
            "error": str(e),
            "status": "failed"
        }), 500

@app.route("/api/security/quarantine", methods=["POST"])
def quarantine_infected_blocks():
    """Quarantine infected blocks"""
    try:
        if 'username' not in session or session.get('role') != 'admin':
            return jsonify({"error": "Unauthorized - Admin access required"}), 403
        
        # Get optional parameters
        request_data = request.get_json() or {}
        severity_threshold = request_data.get('severity_threshold', 'HIGH')
        
        quarantine_results = quarantine_compromised_blocks()
        
        log_security_event('quarantine_action', 'completed', {
            'triggered_by': session['username'],
            'blocks_quarantined': len(quarantine_results.get('quarantined', [])),
            'severity_threshold': severity_threshold
        })
        
        return jsonify({
            'status': 'completed',
            'results': quarantine_results,
            'triggered_by': session['username'],
            'timestamp': time.time()
        }), 200
        
    except Exception as e:
        print(f"Error quarantining blocks: {e}")
        return jsonify({
            "error": str(e),
            "status": "failed"
        }), 500

@app.route("/api/security/quarantine/<int:block_id>", methods=["POST"])
def quarantine_specific_block(block_id):
    """Quarantine a specific block"""
    try:
        if 'username' not in session or session.get('role') != 'admin':
            return jsonify({"error": "Unauthorized - Admin access required"}), 403
        
        global security_analyzer
        
        if not security_analyzer:
            initialize_security_system()
        
        request_data = request.get_json() or {}
        reason = request_data.get('reason', f'Manual quarantine by {session["username"]}')
        
        success = security_analyzer.quarantine_block(block_id, reason)
        
        if success:
            log_security_event('manual_quarantine', 'completed', {
                'block_id': block_id,
                'reason': reason,
                'triggered_by': session['username']
            })
            
            return jsonify({
                'status': 'success',
                'message': f'Block {block_id} quarantined successfully',
                'block_id': block_id,
                'reason': reason
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': f'Block {block_id} not found in quarantine or restoration failed',
                'block_id': block_id
            }), 404
            
    except Exception as e:
        print(f"Error restoring block: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/security/config", methods=["GET", "POST"])
def security_configuration():
    """Get or update security configuration"""
    try:
        if 'username' not in session or session.get('role') != 'admin':
            return jsonify({"error": "Unauthorized - Admin access required"}), 403
        
        global security_monitor
        
        if request.method == "POST":
            config_data = request.get_json()
            
            if not config_data:
                return jsonify({"error": "No configuration data provided"}), 400
            
            # Update security configuration
            old_config = security_config.copy()
            
            security_config.update({
                'enable_auto_reorder': config_data.get('enableAutoReorder', False),
                'trigger_threshold': max(1, min(100, config_data.get('triggerThreshold', 5))),
                'randomness_factor': max(0.0, min(1.0, config_data.get('randomnessFactor', 0.7))),
                'scan_interval': max(60, config_data.get('scanInterval', 3600)),
                'auto_quarantine': config_data.get('autoQuarantine', False)
            })
            
            # Update monitoring if auto-reorder setting changed
            if security_monitor:
                if security_config['enable_auto_reorder'] and not old_config.get('enable_auto_reorder', False):
                    security_monitor.auto_remediation_enabled = True
                    security_monitor.start_monitoring()
                elif not security_config['enable_auto_reorder'] and old_config.get('enable_auto_reorder', False):
                    security_monitor.auto_remediation_enabled = False
                    security_monitor.stop_monitoring()
                
                security_monitor.violation_threshold = security_config['trigger_threshold']
            
            # Save configuration
            save_security_config()
            
            log_security_event('config_update', 'completed', {
                'updated_by': session['username'],
                'old_config': old_config,
                'new_config': security_config
            })
            
            return jsonify({
                'status': 'updated', 
                'config': security_config,
                'monitoring_status': security_monitor.monitoring if security_monitor else False
            }), 200
        
        else:
            # GET request - return current configuration
            current_config = security_config.copy()
            current_config['monitoring_status'] = security_monitor.monitoring if security_monitor else False
            current_config['system_status'] = 'active' if security_monitor and security_monitor.monitoring else 'inactive'
            
            return jsonify({'config': current_config}), 200
            
    except Exception as e:
        print(f"Error managing security configuration: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/security/metrics", methods=["GET"])
def get_detailed_security_metrics():
    """Get detailed security metrics and analytics"""
    try:
        global security_analyzer
        
        if not security_analyzer:
            initialize_security_system()
        
        # Get comprehensive metrics
        metrics = calculate_security_metrics()
        
        # Calculate violation trends
        violation_trends = calculate_violation_trends()
        
        # Risk assessment
        violations = analyze_security_violations()
        risk_assessment = assess_security_risks(violations)
        
        # Performance metrics
        performance_metrics = {
            'average_scan_time': 0,  # You can implement actual timing
            'last_scan_duration': 0,
            'scans_performed_today': get_daily_scan_count(),
            'system_uptime': get_system_uptime_seconds(),
            'memory_usage': get_memory_usage(),
            'storage_usage': get_storage_usage()
        }
        
        detailed_metrics = {
            'current_metrics': metrics,
            'violation_trends': violation_trends,
            'risk_assessment': risk_assessment,
            'performance': performance_metrics,
            'system_health': {
                'blockchain_integrity': metrics.get('integrity_score', 0),
                'monitoring_active': security_monitor.monitoring if security_monitor else False,
                'auto_remediation': security_config.get('enable_auto_reorder', False),
                'last_reorder': security_config.get('last_auto_reorder'),
                'quarantine_capacity': 1000 - len(get_quarantine_data()),  # Assume max 1000
                'scan_frequency': security_config.get('scan_interval', 3600)
            },
            'recommendations': generate_security_recommendations(violations),
            'alerts': generate_security_alerts(metrics, violations)
        }
        
        return jsonify(detailed_metrics), 200
        
    except Exception as e:
        print(f"Error getting detailed metrics: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/security/monitoring", methods=["POST"])
def toggle_security_monitoring():
    """Start or stop security monitoring"""
    try:
        if 'username' not in session or session.get('role') != 'admin':
            return jsonify({"error": "Unauthorized - Admin access required"}), 403
        
        global security_monitor
        
        if not security_monitor:
            initialize_security_system()
        
        request_data = request.get_json() or {}
        action = request_data.get('action', 'toggle')  # 'start', 'stop', or 'toggle'
        
        if action == 'start' or (action == 'toggle' and not security_monitor.monitoring):
            security_monitor.start_monitoring()
            status = 'started'
        elif action == 'stop' or (action == 'toggle' and security_monitor.monitoring):
            security_monitor.stop_monitoring()
            status = 'stopped'
        else:
            status = 'no_change'
        
        log_security_event('monitoring_toggle', status, {
            'action': action,
            'triggered_by': session['username'],
            'monitoring_status': security_monitor.monitoring
        })
        
        return jsonify({
            'status': status,
            'monitoring_active': security_monitor.monitoring,
            'auto_remediation': security_monitor.auto_remediation_enabled
        }), 200
        
    except Exception as e:
        print(f"Error toggling monitoring: {e}")
        return jsonify({"error": str(e)}), 500

# ==================== BLOCKCHAIN API ENDPOINTS ====================

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
        
        # Get security metrics
        security_metrics = calculate_security_metrics()
        
        status_data = {
            "status": "healthy" if is_valid and security_metrics['integrity_score'] >= 80 else "compromised",
            "chain_length": len(blockchain.chain),
            "latest_block": latest_block.to_dict() if latest_block else None,
            "unique_users": user_count,
            "total_databases": database_count,
            "security_metrics": security_metrics,
            "system_info": {
                "uptime": get_system_uptime(),
                "last_backup": get_last_backup_time(),
                "storage_usage": get_storage_usage(),
                "last_security_scan": security_config.get('last_security_scan')
            }
        }
        
        return jsonify(status_data), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== ENHANCED SECURITY ANALYSIS FUNCTIONS ====================

def analyze_security_violations():
    """Enhanced security violation analysis"""
    global security_analyzer
    
    if not security_analyzer:
        initialize_security_system()
    
    try:
        scan_results = security_analyzer.comprehensive_security_scan()
        return scan_results['violations']
    except Exception as e:
        print(f"Error in security analysis: {e}")
        return []

def get_quarantine_data():
    """Get quarantined blocks data"""
    global security_analyzer
    
    if not security_analyzer:
        initialize_security_system()
    
    try:
        return security_analyzer.quarantined_blocks
    except Exception as e:
        print(f"Error getting quarantine data: {e}")
        return []

def perform_comprehensive_scan():
    """Perform comprehensive security scan"""
    global security_analyzer
    
    if not security_analyzer:
        initialize_security_system()
    
    try:
        scan_results = security_analyzer.comprehensive_security_scan()
        
        # Additional analysis
        recommendations = []
        if len(scan_results['violations']) > 0:
            recommendations.append("Review and address security violations")
        if len([v for v in scan_results['violations'] if v['severity'] == 'CRITICAL']) > 0:
            recommendations.append("Immediate attention required for critical violations")
        if len(scan_results['violations']) > 10:
            recommendations.append("Consider enabling auto-remediation")
        
        return {
            'violations': scan_results['violations'],
            'quarantined': security_analyzer.quarantined_blocks,
            'metrics': calculate_security_metrics(),
            'recommendations': recommendations,
            'scan_details': {
                'blocks_analyzed': scan_results['blocks_analyzed'],
                'scan_timestamp': scan_results['scan_timestamp']
            }
        }
        
    except Exception as e:
        print(f"Error in comprehensive scan: {e}")
        return {
            'violations': [],
            'quarantined': [],
            'metrics': {},
            'recommendations': [f"Error during scan: {str(e)}"]
        }

def perform_chain_reorder():
    """Perform blockchain reorder for security"""
    global security_analyzer
    
    try:
        # Trigger blockchain validation which will perform reordering if needed
        original_length = len(blockchain.chain)
        is_valid = blockchain.is_chain_valid()
        
        new_length = len(blockchain.chain)
        blocks_affected = original_length - new_length
        
        # Update security configuration
        security_config['reorder_count'] = security_config.get('reorder_count', 0) + 1
        security_config['last_auto_reorder'] = time.time()
        save_security_config()
        
        return {
            'status': 'completed',
            'blocks_affected': blocks_affected,
            'original_length': original_length,
            'new_length': new_length,
            'reorder_type': 'security_remediation',
            'timestamp': time.time(),
            'chain_valid': is_valid
        }
        
    except Exception as e:
        print(f"Error in chain reorder: {e}")
        return {
            'status': 'failed',
            'error': str(e),
            'blocks_affected': 0
        }

def quarantine_compromised_blocks():
    """Quarantine compromised blocks"""
    global security_analyzer
    
    if not security_analyzer:
        initialize_security_system()
    
    try:
        violations = security_analyzer.comprehensive_security_scan()['violations']
        quarantined = []
        
        for violation in violations:
            if violation['severity'] in ['CRITICAL', 'HIGH']:
                success = security_analyzer.quarantine_block(
                    violation['block_id'],
                    f"Bulk quarantine: {violation['violation_type']}"
                )
                if success:
                    quarantined.append(violation['block_id'])
        
        return {
            'quarantined': quarantined,
            'total_quarantined': len(quarantined),
            'timestamp': time.time()
        }
        
    except Exception as e:
        print(f"Error quarantining blocks: {e}")
        return {
            'quarantined': [],
            'total_quarantined': 0,
            'error': str(e)
        }

def calculate_security_metrics():
    """Calculate comprehensive security metrics"""
    global security_analyzer
    
    if not security_analyzer:
        return {
            'integrity_score': 100,
            'total_violations': 0,
            'critical_violations': 0,
            'chain_length': len(blockchain.chain)
        }
    
    try:
        violations = security_analyzer.comprehensive_security_scan()['violations']
        chain_length = len(blockchain.chain)
        
        # Calculate integrity score
        critical_violations = len([v for v in violations if v['severity'] == 'CRITICAL'])
        high_violations = len([v for v in violations if v['severity'] == 'HIGH'])
        
        integrity_score = 100
        if chain_length > 0:
            # Deduct points for violations
            integrity_score -= (critical_violations * 25)  # 25 points per critical
            integrity_score -= (high_violations * 15)      # 15 points per high
            integrity_score = max(0, integrity_score)
        
        # Additional metrics
        auth_blocks = sum(1 for block in blockchain.chain 
                         if hasattr(block, 'data') and isinstance(block.data, dict) 
                         and block.data.get('action') == 'authenticate')
        
        db_blocks = sum(1 for block in blockchain.chain 
                       if hasattr(block, 'data') and isinstance(block.data, dict) 
                       and block.data.get('action') in ['create_database', 'store_item'])
        
        return {
            'integrity_score': integrity_score,
            'total_violations': len(violations),
            'critical_violations': critical_violations,
            'high_violations': high_violations,
            'medium_violations': len([v for v in violations if v['severity'] == 'MEDIUM']),
            'low_violations': len([v for v in violations if v['severity'] == 'LOW']),
            'chain_length': chain_length,
            'auth_operations': auth_blocks,
            'database_operations': db_blocks,
            'quarantined_blocks': len(security_analyzer.quarantined_blocks),
            'reorder_count': security_config.get('reorder_count', 0),
            'data_recovery_count': security_config.get('data_recovery_count', 0),
            'last_scan': security_config.get('last_security_scan'),
            'monitoring_active': security_monitor.monitoring if security_monitor else False
        }
        
    except Exception as e:
        print(f"Error calculating security metrics: {e}")
        return {
            'integrity_score': 0,
            'total_violations': 0,
            'error': str(e)
        }

def assess_threat_level(violations, quarantined):
    """Assess current threat level"""
    critical_count = len([v for v in violations if v['severity'] == 'CRITICAL'])
    high_count = len([v for v in violations if v['severity'] == 'HIGH'])
    
    if critical_count >= 3:
        return 'CRITICAL'
    elif critical_count >= 1 or high_count >= 5:
        return 'HIGH'
    elif high_count >= 2:
        return 'MEDIUM'
    elif len(violations) > 0:
        return 'LOW'
    else:
        return 'NONE'

def get_security_timeline():
    """Get security event timeline"""
    timeline_file = 'security_timeline.json'
    timeline = []
    
    if os.path.exists(timeline_file):
        try:
            with open(timeline_file, 'r') as f:
                timeline = json.load(f)
        except:
            timeline = []
    
    # Add recent violations to timeline
    violations = analyze_security_violations()
    for violation in violations[-10:]:  # Last 10 violations
        timeline.append({
            'type': 'violation',
            'timestamp': violation['timestamp'],
            'title': f"Security Violation Detected",
            'description': f"{violation['violation_type']} in Block #{violation['block_id']}: {violation['description']}"
        })
    
    # Sort by timestamp (newest first)
    timeline.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return timeline[:50]  # Return last 50 events

def log_security_event(event_type, status, details):
    """Log security events to centralized forensics directory"""
    try:
        forensics_dir = chain_manager.subdirs['forensics']
        timeline_file = forensics_dir / 'security_timeline.json'
        
        event = {
            'type': event_type,
            'status': status,
            'timestamp': time.time(),
            'title': f"{event_type.title().replace('_', ' ')} {status.title()}",
            'description': f"{event_type.replace('_', ' ').title()} was {status}",
            'details': details
        }
        
        timeline = []
        if timeline_file.exists():
            try:
                with open(timeline_file, 'r') as f:
                    timeline = json.load(f)
            except:
                timeline = []
        
        timeline.append(event)
        timeline = timeline[-1000:]  # Keep only last 1000 events
        
        with open(timeline_file, 'w') as f:
            json.dump(timeline, f, indent=2)
            
    except Exception as e:
        print(f"Failed to log security event: {e}")

def save_security_config():
    """Save security configuration to centralized location"""
    try:
        config_file = chain_manager.base_dir / 'security_config.json'
        with open(config_file, 'w') as f:
            json.dump(security_config, f, indent=2)
    except Exception as e:
        print(f"Failed to save security config: {e}")

def load_security_config():
    """Load security configuration from centralized location"""
    global security_config
    try:
        config_file = chain_manager.base_dir / 'security_config.json'
        if config_file.exists():
            with open(config_file, 'r') as f:
                loaded_config = json.load(f)
                security_config.update(loaded_config)
    except Exception as e:
        print(f"Failed to load security config: {e}")

def ensure_security_files():
    """Ensure all security-related files exist with proper structure"""
    try:
        # Security configuration file
        if not os.path.exists('security_config.json'):
            default_config = {
                'enable_auto_reorder': False,
                'trigger_threshold': 5,
                'randomness_factor': 0.7,
                'scan_interval': 3600,
                'auto_quarantine': False,
                'system_start_time': time.time(),
                'reorder_count': 0,
                'data_recovery_count': 0
            }
            with open('security_config.json', 'w') as f:
                json.dump(default_config, f, indent=2)
            print("📄 Created default security configuration")
        
        # Security timeline file
        if not os.path.exists('security_timeline.json'):
            with open('security_timeline.json', 'w') as f:
                json.dump([], f)
            print("📄 Created security timeline file")
        
        # Quarantine file
        if not os.path.exists('quarantined_blocks.json'):
            with open('quarantined_blocks.json', 'w') as f:
                json.dump([], f)
            print("📄 Created quarantine file")
        
        # Create directories
        os.makedirs('logs', exist_ok=True)
        os.makedirs('security_reports', exist_ok=True)
        os.makedirs('backups', exist_ok=True)
        
        print("✅ Security file structure verified")
        
    except Exception as e:
        print(f"❌ Error ensuring security files: {e}")

# ==================== HELPER FUNCTIONS FOR SECURITY API ====================

def generate_security_recommendations(violations):
    """Generate security recommendations based on violations"""
    recommendations = []
    
    if not violations:
        recommendations.append("✅ System is secure - no violations detected")
        return recommendations
    
    critical_count = len([v for v in violations if v['severity'] == 'CRITICAL'])
    high_count = len([v for v in violations if v['severity'] == 'HIGH'])
    
    if critical_count > 0:
        recommendations.append(f"🚨 Immediate attention required: {critical_count} critical violations detected")
        recommendations.append("🔧 Run blockchain validation to trigger automatic quarantine")
    
    if high_count > 3:
        recommendations.append(f"⚠️ Review {high_count} high-severity violations")
        recommendations.append("🛡️ Enable automatic remediation for faster response")
    
    if len(violations) > 10:
        recommendations.append("📊 High violation count detected - review security policies")
    
    # Check violation types
    violation_types = [v['violation_type'] for v in violations]
    if 'HASH_MISMATCH' in violation_types:
        recommendations.append("🔐 Hash mismatches detected - verify data integrity")
    if 'CHAIN_BREAK' in violation_types:
        recommendations.append("⛓️ Chain continuity issues found - immediate repair needed")
    
    recommendations.append(f"📁 All quarantine data stored in: {chain_manager.subdirs['quarantine']}")
    
    return recommendations

def generate_security_alerts(metrics, violations):
    """Generate security alerts based on current state"""
    alerts = []
    
    integrity_score = metrics.get('integrity_score', 100)
    if integrity_score < 50:
        alerts.append({
            'level': 'critical',
            'message': f'System integrity critically low: {integrity_score}%',
            'action': 'immediate_attention'
        })
    elif integrity_score < 80:
        alerts.append({
            'level': 'warning',
            'message': f'System integrity below optimal: {integrity_score}%',
            'action': 'review_required'
        })
    
    critical_violations = len([v for v in violations if v['severity'] == 'CRITICAL'])
    if critical_violations > 0:
        alerts.append({
            'level': 'critical',
            'message': f'{critical_violations} critical security violations active',
            'action': 'immediate_remediation'
        })
    
    quarantined_count = metrics.get('quarantined_blocks', 0)
    if quarantined_count > 10:
        alerts.append({
            'level': 'warning',
            'message': f'{quarantined_count} blocks in quarantine',
            'action': 'review_quarantine'
        })
    
    return alerts

def calculate_violation_trends():
    """Calculate violation trends over time"""
    try:
        # Get violations from the last 24 hours, 7 days, 30 days
        current_time = time.time()
        day_ago = current_time - 86400
        week_ago = current_time - 604800
        month_ago = current_time - 2592000
        
        recent_violations = []
        if security_analyzer:
            recent_violations = security_analyzer.violation_history
        
        # Count violations by time period
        daily_count = len([v for v in recent_violations if v['timestamp'] >= day_ago])
        weekly_count = len([v for v in recent_violations if v['timestamp'] >= week_ago])
        monthly_count = len([v for v in recent_violations if v['timestamp'] >= month_ago])
        
        # Violation types trend
        violation_types_trend = defaultdict(int)
        for violation in recent_violations:
            if violation['timestamp'] >= week_ago:
                violation_types_trend[violation['violation_type']] += 1
        
        return {
            'daily_violations': daily_count,
            'weekly_violations': weekly_count,
            'monthly_violations': monthly_count,
            'violation_types_trend': dict(violation_types_trend),
            'severity_distribution': {
                'CRITICAL': len([v for v in recent_violations if v['severity'] == 'CRITICAL' and v['timestamp'] >= week_ago]),
                'HIGH': len([v for v in recent_violations if v['severity'] == 'HIGH' and v['timestamp'] >= week_ago]),
                'MEDIUM': len([v for v in recent_violations if v['severity'] == 'MEDIUM' and v['timestamp'] >= week_ago]),
                'LOW': len([v for v in recent_violations if v['severity'] == 'LOW' and v['timestamp'] >= week_ago])
            }
        }
        
    except Exception as e:
        print(f"Error calculating violation trends: {e}")
        return {
            'daily_violations': 0,
            'weekly_violations': 0,
            'monthly_violations': 0,
            'violation_types_trend': {},
            'severity_distribution': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        }

def assess_security_risks(violations):
    """Assess current security risks"""
    risks = {
        'data_integrity': 'LOW',
        'chain_continuity': 'LOW',
        'unauthorized_access': 'LOW',
        'system_availability': 'LOW',
        'overall_risk': 'LOW'
    }
    
    try:
        for violation in violations:
            # Assess data integrity risk
            if violation['violation_type'] in ['HASH_MISMATCH', 'DATA_STRUCTURE_INVALID', 'DATA_CORRUPTION']:
                if violation['severity'] == 'CRITICAL':
                    risks['data_integrity'] = 'CRITICAL'
                elif violation['severity'] == 'HIGH' and risks['data_integrity'] != 'CRITICAL':
                    risks['data_integrity'] = 'HIGH'
                elif risks['data_integrity'] == 'LOW':
                    risks['data_integrity'] = 'MEDIUM'
            
            # Assess chain continuity risk
            if violation['violation_type'] in ['CHAIN_BREAK', 'TIMESTAMP_VIOLATION']:
                if violation['severity'] == 'CRITICAL':
                    risks['chain_continuity'] = 'CRITICAL'
                elif violation['severity'] == 'HIGH' and risks['chain_continuity'] != 'CRITICAL':
                    risks['chain_continuity'] = 'HIGH'
            
            # Assess unauthorized access risk
            if violation['violation_type'] in ['SUSPICIOUS_AUTH_PATTERN', 'UNAUTHORIZED_DB_OPERATION']:
                if violation['severity'] in ['CRITICAL', 'HIGH']:
                    risks['unauthorized_access'] = 'HIGH'
                elif risks['unauthorized_access'] == 'LOW':
                    risks['unauthorized_access'] = 'MEDIUM'
        
        # Calculate overall risk
        risk_levels = list(risks.values())
        if 'CRITICAL' in risk_levels:
            risks['overall_risk'] = 'CRITICAL'
        elif 'HIGH' in risk_levels:
            risks['overall_risk'] = 'HIGH'
        elif 'MEDIUM' in risk_levels:
            risks['overall_risk'] = 'MEDIUM'
        
        return risks
        
    except Exception as e:
        print(f"Error assessing security risks: {e}")
        return risks

def get_daily_scan_count():
    """Get number of scans performed today"""
    try:
        timeline_file = 'security_timeline.json'
        if os.path.exists(timeline_file):
            with open(timeline_file, 'r') as f:
                events = json.load(f)
                
            today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
            scan_count = len([e for e in events 
                            if e.get('type') == 'security_scan' and e.get('timestamp', 0) >= today_start])
            return scan_count
        
        return 0
    except:
        return 0

def get_system_uptime_seconds():
    """Get system uptime in seconds"""
    return time.time() - security_config.get('system_start_time', time.time())

def get_memory_usage():
    """Get current memory usage"""
    try:
        import psutil
        return {
            'percent': psutil.virtual_memory().percent,
            'available': psutil.virtual_memory().available,
            'total': psutil.virtual_memory().total
        }
    except ImportError:
        return {'percent': 0, 'available': 0, 'total': 0, 'note': 'psutil not available'}

# ==================== EXISTING UTILITY FUNCTIONS ====================

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

def get_system_uptime():
    """Get system uptime"""
    uptime_seconds = get_system_uptime_seconds()
    if uptime_seconds < 60:
        return f"{int(uptime_seconds)} seconds"
    elif uptime_seconds < 3600:
        return f"{int(uptime_seconds / 60)} minutes"
    elif uptime_seconds < 86400:
        return f"{int(uptime_seconds / 3600)} hours"
    else:
        return f"{int(uptime_seconds / 86400)} days"

def get_last_backup_time():
    """Get last backup time"""
    try:
        backup_files = glob.glob('backups/*.json')
        if backup_files:
            latest_backup = max(backup_files, key=os.path.getmtime)
            backup_time = os.path.getmtime(latest_backup)
            return datetime.fromtimestamp(backup_time).strftime('%Y-%m-%d %H:%M:%S')
        return "No backups found"
    except:
        return "Backup info unavailable"

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
        
        # Calculate total storage for all related files
        total_storage = blockchain_file_size
        
        # Add security files
        security_files = ['security_config.json', 'security_timeline.json', 'quarantined_blocks.json']
        for file_path in security_files:
            if os.path.exists(file_path):
                total_storage += os.path.getsize(file_path)
        
        # Add backup files
        backup_files = glob.glob('backups/*.json')
        for file_path in backup_files:
            total_storage += os.path.getsize(file_path)
        
        return {
            "blockchain_file_size": blockchain_file_size,
            "total_storage": total_storage,
            "human_readable": format_file_size(total_storage)
        }
    except Exception as e:
        return {"error": f"Unable to calculate storage usage: {e}"}

def format_file_size(size_bytes):
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

# ==================== DATABASE MANAGEMENT ROUTES ====================

@app.route("/tables/<db_name>")
def list_tables(db_name):
    """Enhanced list tables in a database"""
    if 'username' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))
    
    try:
        # Get the database path for the given name
        all_dbs = db_manager.list_databases(session['username'], session.get('role'))
        db = next((d for d in all_dbs if d["name"] == db_name), None)
        
        if not db:
            flash(f"Database '{db_name}' not found or you don't have access to it!")
            return redirect(url_for('home'))
        
        # Read the schema file to get tables
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
    """Enhanced view records in a table with better error handling"""
    if 'username' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))
    
    try:
        # Verify user has access to this database
        databases = db_manager.list_databases(session['username'], session.get('role'))
        db_exists = any(db['name'] == db_name for db in databases)
        
        if not db_exists:
            flash(f"Database '{db_name}' not found or you don't have access to it.")
            return redirect(url_for('home'))
        
        # Get database items from the blockchain
        items = db_manager.get_database_items(db_name, session['username'], session.get('role'))
        
        # Filter items that belong to the requested table
        table_items = []
        for item in items:
            try:
                if not item.get("path") or not os.path.exists(item["path"]):
                    continue
                    
                with open(item["path"], "r", encoding='utf-8') as f:
                    data = json.load(f)
                    
                if data.get("table") == table_name:
                    # Extract ID from filename
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
                    
                    # Extract and validate data
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
        
        # Determine columns and format rows
        columns = []
        rows = []
        
        if table_items:
            # Get all possible column names
            all_columns = set()
            for item in table_items:
                if isinstance(item["data"], dict):
                    all_columns.update(item["data"].keys())
            columns = sorted(list(all_columns))
            
            if not columns:
                columns = ["data"]
            
            # Format data as rows
            for item in table_items:
                row = [item["id"]]  # Start with ID
                
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
            
            # Add ID column at the beginning
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
        # Verify access to database
        databases = db_manager.list_databases(session['username'], session.get('role'))
        db_exists = any(db['name'] == db_name for db in databases)
        
        if not db_exists:
            flash(f"Database '{db_name}' not found or you don't have access to it.")
            return redirect(url_for('home'))
        
        if request.method == "GET":
            # Get table schema
            table_schema = get_table_schema(db_name, table_name)
            fields = table_schema.get("fields", {}) if table_schema else {}
            
            return render_template("add_record.html", 
                                 db_name=db_name, 
                                 table_name=table_name,
                                 fields=fields)
        
        elif request.method == "POST":
            # Process form data
            record_data = {}
            
            # Handle dynamic fields
            field_names = request.form.getlist('field_names[]')
            field_values = request.form.getlist('field_values[]')
            
            # Process regular form fields
            for key, value in request.form.items():
                if key not in ['field_names[]', 'field_values[]'] and value.strip():
                    record_data[key] = value.strip()
            
            # Process dynamic fields
            for i, field_name in enumerate(field_names):
                if field_name.strip() and i < len(field_values) and field_values[i].strip():
                    record_data[field_name.strip()] = field_values[i].strip()
            
            if not record_data:
                flash("Please provide at least one field with data.")
                return redirect(url_for('add_record', db_name=db_name, table_name=table_name))
            
            # Create record
            try:
                timestamp = int(time.time())
                record_id = f"{table_name}_{timestamp}"
                
                full_data = {
                    "table": table_name,
                    "data": record_data,
                    "timestamp": datetime.now().isoformat(),
                    "created_by": session['username']
                }
                
                success = db_manager.add_item(db_name, record_id, full_data, session['username'])
                
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
        # Verify access
        databases = db_manager.list_databases(session['username'], session.get('role'))
        db_exists = any(db['name'] == db_name for db in databases)
        
        if not db_exists:
            if request.method == "DELETE":
                return jsonify({"success": False, "message": "Database not found"}), 404
            flash(f"Database '{db_name}' not found.")
            return redirect(url_for('home'))
        
        # Find the record to delete
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
        
        # Delete the record
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
                
                # Log database creation
                log_security_event('database_creation', 'success', {
                    'database_name': db_name,
                    'created_by': session['username'],
                    'table_count': table_count,
                    'timestamp': time.time()
                })
                
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

# ==================== STARTUP AND INITIALIZATION ====================

def verify_system_integrity():
    """Verify system integrity on startup"""
    try:
        print("🔍 Verifying system integrity...")
        
        # Check blockchain file exists and is valid
        blockchain_file = "blockchain_db.json"
        if os.path.exists("system_chains/active/blockchain_db.json"):
            blockchain_file = "system_chains/active/blockchain_db.json"
        
        if not os.path.exists(blockchain_file):
            print("⚠️  Blockchain database not found - will create new genesis block")
            return True
        
        # Verify blockchain can be loaded
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
            
            # Ensure backups directory exists
            os.makedirs('backups', exist_ok=True)
            
            # Create backup
            shutil.copy2(blockchain_file, backup_path)
            print(f"💾 Startup backup created: {backup_name}")
            
            # Keep only last 10 startup backups
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
        # Initialize security system before starting the server
        print("🔗 Initializing Blockchain Database System...")
        print("=" * 60)
        
        # Verify system integrity first
        verify_system_integrity()
        
        # Create startup backup
        create_startup_backup()
        
        # Load security configuration on startup
        load_security_config()
        ensure_security_files()
        
        # Initialize security components
        print("🛡️ Initializing security systems...")
        initialize_security_system()
        
        # Record system startup time for uptime tracking
        security_config['system_start_time'] = time.time()
        save_security_config()
        
        # Initialize security monitoring if enabled
        if security_config.get('enable_auto_reorder', False):
            print("🔄 Auto-remediation enabled - starting monitoring...")
            if security_monitor:
                security_monitor.auto_remediation_enabled = True
                security_monitor.start_monitoring()
        
        # Log system startup
        log_security_event('system_startup', 'success', {
            'timestamp': time.time(),
            'security_features_enabled': True,
            'auto_monitoring': security_config.get('enable_auto_reorder', False),
            'version': '2.0',
            'security_modules': ['SecurityAnalyzer', 'SecurityMonitor', 'EnhancedQuarantine']
        })
        
        # Perform initial security scan
        print("🔍 Performing initial security scan...")
        if security_analyzer:
            initial_scan = security_analyzer.comprehensive_security_scan()
            violations = initial_scan.get('violations', [])
            if violations:
                critical_count = len([v for v in violations if v['severity'] == 'CRITICAL'])
                high_count = len([v for v in violations if v['severity'] == 'HIGH'])
                print(f"⚠️ Initial scan found {len(violations)} violations (Critical: {critical_count}, High: {high_count})")
            else:
                print("✅ Initial security scan: No violations detected")
        
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
        print(f"   • Real-time monitoring: {'ENABLED' if security_config.get('enable_auto_reorder', False) else 'DISABLED'}")
        print(f"   • Auto-remediation:     {'ENABLED' if security_config.get('enable_auto_reorder', False) else 'DISABLED'}")
        print(f"   • Quarantine system:    ENABLED")
        print(f"   • Violation tracking:   ENABLED")
        print(f"   • Forensic logging:     ENABLED")
        print("=" * 60)
        print("🔥 Server starting... Press Ctrl+C to stop")
        print("=" * 60)
        
        # Register cleanup function for graceful shutdown
        import atexit
        
        def cleanup_on_exit():
            print("\n🛑 Shutting down Blockchain Database System...")
            if security_monitor and security_monitor.monitoring:
                print("🛡️ Stopping security monitoring...")
                security_monitor.stop_monitoring()
            
            # Log system shutdown
            log_security_event('system_shutdown', 'success', {
                'timestamp': time.time(),
                'uptime_seconds': time.time() - security_config.get('system_start_time', time.time()),
                'graceful_shutdown': True
            })
            print("✅ Shutdown complete")
        
        atexit.register(cleanup_on_exit)
        
        # Start the Flask application
        app.run(host="0.0.0.0", port=1337, debug=False, threaded=True)
        
    except KeyboardInterrupt:
        print("\n🛑 Received shutdown signal...")
        if security_monitor and security_monitor.monitoring:
            print("🛡️ Stopping security monitoring...")
            security_monitor.stop_monitoring()
        
        log_security_event('system_shutdown', 'manual', {
            'timestamp': time.time(),
            'shutdown_type': 'keyboard_interrupt'
        })
        print("✅ Server stopped")
        
    except Exception as e:
        print(f"❌ Critical error during startup: {e}")
        
        # Log startup error
        log_security_event('system_startup', 'failed', {
            'timestamp': time.time(),
            'error': str(e),
            'critical': True
        })
        
        import traceback
        traceback.print_exc()
        
        print("\n🔧 Troubleshooting tips:")
        print("   • Check if port 1337 is available")
        print("   • Verify blockchain database files exist")
        print("   • Ensure proper permissions for file access")
        print("   • Check system dependencies")
        
        exit(1)