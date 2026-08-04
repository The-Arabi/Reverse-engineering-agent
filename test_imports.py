#!/usr/bin/env python3
# Test script to verify imports work

try:
    from knowledge_base_enhanced import enhanced_kb, add_fact, add_hypothesis, add_experiment
    print("SUCCESS: All imports from knowledge_base_enhanced worked")
    print(f"Knowledge base type: {type(enhanced_kb)}")
except Exception as e:
    print(f"ERROR: Failed to import from knowledge_base_enhanced: {e}")
    import traceback
    traceback.print_exc()