# Ghidra headless script - get cross-references
# @category RE_Lab
# @author RE Lab
import json

program = getCurrentProgram()
ref_mgr = program.getReferenceManager()

# Read target address from property (set by MCP server via env or property file)
import java.lang.System as JSystem
target_addr_str = JSystem.getProperty("GHIDRA_XREF_ADDR", "")

if not target_addr_str:
    print("GHIDRA_OUTPUT_START")
    print(json.dumps({"error": "No address specified (set GHIDRA_XREF_ADDR property)"}))
    print("GHIDRA_OUTPUT_END")
else:
    addr_factory = program.getAddressFactory()
    addr = addr_factory.getAddress(target_addr_str)

    to_refs = []
    from_refs = []

    for ref in ref_mgr.getReferencesTo(addr):
        to_refs.append({
            "from_address": str(ref.getFromAddress()),
            "to_address": str(ref.getToAddress()),
            "reference_type": str(ref.getReferenceType()),
        })

    for ref in ref_mgr.getReferencesFrom(addr):
        from_refs.append({
            "from_address": str(ref.getFromAddress()),
            "to_address": str(ref.getToAddress()),
            "reference_type": str(ref.getReferenceType()),
        })

    print("GHIDRA_OUTPUT_START")
    print(json.dumps({"to": to_refs, "from": from_refs}))
    print("GHIDRA_OUTPUT_END")
