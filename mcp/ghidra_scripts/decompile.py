# Ghidra headless script - decompile function
# @category RE_Lab
# @author RE Lab
import json
import java.lang.System as JSystem
from ghidra.app.decompiler import DecompInterface

program = getCurrentProgram()
listing = program.getListing()
addr_factory = program.getAddressFactory()

target_addr_str = JSystem.getProperty("GHIDRA_DECOMP_ADDR", "")

if not target_addr_str:
    print("GHIDRA_OUTPUT_START")
    print(json.dumps({"error": "No address specified (set GHIDRA_DECOMP_ADDR property)"}))
    print("GHIDRA_OUTPUT_END")
else:
    addr = addr_factory.getAddress(target_addr_str)
    func = listing.getFunctionAt(addr)

    if not func:
        func = listing.getFunctionContaining(addr)

    if func:
        decomp = DecompInterface()
        decomp.openProgram(program)
        result = decomp.decompileFunction(func, 30, monitor)

        if result and result.decompileCompleted():
            c_code = result.getDecompiledFunction().getC()
            signature = str(func.getSignature())
            print("GHIDRA_OUTPUT_START")
            print(json.dumps({
                "function": str(func.getName()),
                "address": str(func.getEntryPoint()),
                "signature": signature,
                "decompiled_code": c_code,
                "error_messages": [str(e) for e in result.getErrorMessageBytes().toString()] if result.getErrorMessageBytes() else [],
            }))
            print("GHIDRA_OUTPUT_END")
        else:
            error_msg = str(result.getErrorMessage()) if result else "Decompilation failed"
            print("GHIDRA_OUTPUT_START")
            print(json.dumps({"error": error_msg}))
            print("GHIDRA_OUTPUT_END")

        decomp.dispose()
    else:
        print("GHIDRA_OUTPUT_START")
        print(json.dumps({"error": f"No function found at address {target_addr_str}"}))
        print("GHIDRA_OUTPUT_END")
