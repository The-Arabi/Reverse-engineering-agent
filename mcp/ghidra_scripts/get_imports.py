# Ghidra headless script - get imports
# @category RE_Lab
# @author RE Lab
import json

program = getCurrentProgram()
symbol_table = program.getSymbolTable()
results = []

for sym in symbol_table.getExternalSymbols():
    results.append({
        "name": str(sym.getName()),
        "address": str(sym.getAddress()),
        "library": str(sym.getParentNamespace()) if sym.getParentNamespace() else "",
        "source_type": str(sym.getSource()),
    })

print("GHIDRA_OUTPUT_START")
print(json.dumps(results))
print("GHIDRA_OUTPUT_END")
