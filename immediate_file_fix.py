#!/usr/bin/env python3
"""
IMMEDIATE FIX: Run this script to move misplaced files to correct directories
"""

import shutil
from pathlib import Path
import glob

def fix_misplaced_files():
    """Move all misplaced blockchain security files to correct directories"""
    print("🔧 [EMERGENCY CLEANUP] Moving misplaced files...")
    print("=" * 50)
    
    base_dir = Path("system_chains")
    
    # Ensure all subdirectories exist
    subdirs = ['fallbacks', 'quarantine', 'forensics', 'backups']
    for subdir in subdirs:
        (base_dir / subdir).mkdir(parents=True, exist_ok=True)
        print(f"📁 Ensured directory: system_chains/{subdir}/")
    
    moved_count = 0
    
    # Fix 1: Enhanced fallback files (currently in /system_chains)
    print("\n🔄 Fixing enhanced_fallback files...")
    for file_path in base_dir.glob("enhanced_fallback*.json"):
        if file_path.parent == base_dir:  # Only move if in wrong location
            dest = base_dir / "fallbacks" / file_path.name
            try:
                shutil.move(str(file_path), str(dest))
                print(f"  ✅ {file_path.name} → fallbacks/")
                moved_count += 1
            except Exception as e:
                print(f"  ❌ Failed: {e}")
    
    # Fix 2: Forensic report files (currently in /system_chains)
    print("\n🔍 Fixing forensic_report files...")
    for file_path in base_dir.glob("forensic_report*.json"):
        if file_path.parent == base_dir:
            dest = base_dir / "forensics" / file_path.name
            try:
                shutil.move(str(file_path), str(dest))
                print(f"  ✅ {file_path.name} → forensics/")
                moved_count += 1
            except Exception as e:
                print(f"  ❌ Failed: {e}")
    
    # Fix 3: Clean block files (currently in root directory)
    print("\n💾 Fixing clean_block files...")
    root_dir = Path(".")
    for pattern in ["clean_block*.json", "clean_blockchain*.json"]:
        for file_path in root_dir.glob(pattern):
            if file_path.parent == root_dir:  # Only move if in root
                dest = base_dir / "backups" / file_path.name
                try:
                    shutil.move(str(file_path), str(dest))
                    print(f"  ✅ {file_path.name} → backups/")
                    moved_count += 1
                except Exception as e:
                    print(f"  ❌ Failed: {e}")
    
    # Bonus: Fix other common misplaced files
    print("\n🧹 Cleaning up other misplaced files...")
    
    # Move quarantined files to quarantine directory
    for file_path in base_dir.glob("quarantined_blocks*.json"):
        if file_path.parent == base_dir:
            dest = base_dir / "quarantine" / file_path.name
            try:
                shutil.move(str(file_path), str(dest))
                print(f"  ✅ {file_path.name} → quarantine/")
                moved_count += 1
            except Exception as e:
                print(f"  ❌ Failed: {e}")
    
    # Move infected files from root to quarantine
    for file_path in root_dir.glob("infected_blocks*.json"):
        if file_path.parent == root_dir:
            dest = base_dir / "quarantine" / file_path.name
            try:
                shutil.move(str(file_path), str(dest))
                print(f"  ✅ {file_path.name} → quarantine/")
                moved_count += 1
            except Exception as e:
                print(f"  ❌ Failed: {e}")
    
    print("=" * 50)
    print(f"🎉 [CLEANUP COMPLETE] Moved {moved_count} files")
    
    # Show final structure
    print("\n📂 Final directory structure:")
    for subdir in subdirs:
        subdir_path = base_dir / subdir
        files = list(subdir_path.glob("*.json"))
        print(f"  system_chains/{subdir}/: {len(files)} files")
        for file in files[:2]:  # Show first 2 files
            print(f"    - {file.name}")
        if len(files) > 2:
            print(f"    ... and {len(files) - 2} more")

if __name__ == "__main__":
    fix_misplaced_files()