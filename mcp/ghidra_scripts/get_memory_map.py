# Ghidra headless script - get memory map / sections
# @category RE_Lab
# @author RE Lab
import json

program = getCurrentProgram()
memory = program.getMemory()

results = []
for block in memory.getBlocks():
    results.append({
        "name": str(block.getName()),
        "start": str(block.getStart()),
        "end": str(block.getEnd()),
        "size": block.getSize(),
        "executable": block.isExecute(),
        "readable": block.isRead(),
        "writable": block.isWrite(),
    })

print("GHIDRA_OUTPUT_START")
print(json.dumps(results))
print("GHIDRA_OUTPUT_END")
