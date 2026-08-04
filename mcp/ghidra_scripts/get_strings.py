# Ghidra headless script - extract strings
# @category RE_Lab
# @author RE Lab
from ghidra.program.model.listing import CodeUnit
import json

program = getCurrentProgram()
listing = program.getListing()
memory = program.getMemory()

results = []
for block in memory.getBlocks():
    for codeUnit in listing.getCodeUnits(block.getStart(), block.getEnd(), True):
        for ref in codeUnit.getReferencesFrom():
            pass  # placeholder to iterate
    # Walk defined data in the block
    iter = listing.getDefinedData(block.getStart(), True)
    while iter.hasNext():
        du = iter.next()
        val = du.getDefaultValueRepresentation()
        if val and len(val) > 3:
            results.append({
                "address": str(du.getAddress()),
                "string": val.strip('"'),
                "length": len(val),
                "section": str(block.getName()),
                "data_type": str(du.getDataType()),
            })

print("GHIDRA_OUTPUT_START")
print(json.dumps(results))
print("GHIDRA_OUTPUT_END")
