# Ghidra headless script - list functions
# @category RE_Lab
# @author RE Lab
from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompInterface

program = getCurrentProgram()
listing = program.getListing()
functions = listing.getFunctions(True)

results = []
for func in functions:
    results.append({
        "name": str(func.getName()),
        "address": str(func.getEntryPoint()),
        "size": func.getBody().getNumAddresses(),
        "is_thunk": func.isThunk(),
        "calling_convention": str(func.getCallingConventionName()),
        "param_count": func.getParameterCount(),
    })

print("GHIDRA_OUTPUT_START")
import json
print(json.dumps(results))
print("GHIDRA_OUTPUT_END")
