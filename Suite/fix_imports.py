#!/usr/bin/env python3
"""
fix_imports.py

Automatically fixes imports in migrated Python files
"""

import sys
import re
from pathlib import Path


IMPORT_REPLACEMENTS = {
    # Advanced bypass engine
    'from advanced_bypass_engine import': 'from core.engines.advanced_bypass_engine import',
    'import advanced_bypass_engine': 'import core.engines.advanced_bypass_engine as advanced_bypass_engine',
    
    # Semantic bypass engine
    'from semantic_bypass_engine import': 'from core.engines.semantic_bypass_engine import',
    'import semantic_bypass_engine': 'import core.engines.semantic_bypass_engine as semantic_bypass_engine',
    
    # Graph attack planner
    'from graph_attack_planner import': 'from core.engines.graph_attack_planner import',
    'import graph_attack_planner': 'import core.engines.graph_attack_planner as graph_attack_planner',
    
    # Intelligent validator
    'from intelligent_bypass_validator import': 'from core.engines.intelligent_bypass_validator import',
    'import intelligent_bypass_validator': 'import core.engines.intelligent_bypass_validator as intelligent_bypass_validator',
    
    # Smart crawler advanced engine
    'from smart_crawler_advanced_engine import': 'from core.engines.smart_crawler_advanced_engine import',
    'import smart_crawler_advanced_engine': 'import core.engines.smart_crawler_advanced_engine as smart_crawler_advanced_engine',
    
    # Enhanced JSON exporter
    'from enhanced_json_exporter import': 'from core.exporters.enhanced_json_exporter import',
    'import enhanced_json_exporter': 'import core.exporters.enhanced_json_exporter as enhanced_json_exporter',
}


def fix_imports_in_file(filepath: Path) -> int:
    """
    Fix imports in a single file
    
    Returns:
        Number of replacements made
    """
    if not filepath.exists():
        print(f"❌ File not found: {filepath}")
        return 0
    
    # Read file
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    replacements_made = 0
    
    # Apply replacements
    for old_import, new_import in IMPORT_REPLACEMENTS.items():
        if old_import in content:
            content = content.replace(old_import, new_import)
            count = original_content.count(old_import)
            replacements_made += count
            print(f"  ✓ Replaced '{old_import}' ({count} occurrences)")
    
    # Write back if changes made
    if replacements_made > 0:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"✅ Fixed {replacements_made} imports in {filepath.name}")
    else:
        print(f"ℹ️  No imports to fix in {filepath.name}")
    
    return replacements_made


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python fix_imports.py <file1.py> [file2.py] ...")
        print("\nExample:")
        print("  python fix_imports.py core/traceroute/application_traceroute_v3_5.py")
        print("  python fix_imports.py core/crawler/smart_vuln_crawler2.py")
        sys.exit(1)
    
    total_replacements = 0
    
    for filepath_str in sys.argv[1:]:
        filepath = Path(filepath_str)
        print(f"\n📝 Processing: {filepath}")
        replacements = fix_imports_in_file(filepath)
        total_replacements += replacements
    
    print(f"\n{'='*60}")
    print(f"✅ Total replacements: {total_replacements}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
