# Ghidra headless script - get function info
# @category RE_Lab
# @author RE Lab
import json
import java.lang.System as JSystem

program = getCurrentProgram()
listing = program.getListing()
addr_factory = program.getAddressFactory()

target_addr_str = JSystem.getProperty("GHIDRA_FUNC_ADDR", "")

if not target_addr_str:
    print("GHIDRA_OUTPUT_START")
    print(json.dumps({"error": "No address specified (set GHIDRA_FUNC_ADDR property)"}))
    print("GHIDRA_OUTPUT_END")
else:
    addr = addr_factory.getAddress(target_addr_str)
    func = listing.getFunctionAt(addr)

    if not func:
        # Try to find function containing the address
        funcs = listing.getFunctionContaining(addr)
        func = funcs

    if func:
        params = []
        for p in func.getParameters():
            params.append({
                "name": str(p.getName()),
                "type": str(p.getDataType()),
                "source": str(p.getSource()),
            })

        body_iter = func.getBody().getAddresses(True)
        first_addr = body_iter.next() if body_iter.hasNext() else None

        result = {
            "name": str(func.getName()),
            "address": str(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses(),
            "is_thunk": func.isThunk(),
            "calling_convention": str(func.getCallingConventionName()),
            "param_count": func.getParameterCount(),
            "parameters": params,
            "return_type": str(func.getReturnType()),
            "signature": str(func.getSignature()),
        }
    else:
        result = {"error": f"No function found at address {target_addr_str}"}

    print("GHIDRA_OUTPUT_START")
    print(json.dumps(result))
    print("GHIDRA_OUTPUT_END")
