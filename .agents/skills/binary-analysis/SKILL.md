---
name: binary-analysis
description: Use when the user wants to analyze an executable binary (ELF, PE, Mach-O). Triggers on binaries, executables, .so files, disassembly, decompilation, ELF analysis, or reverse engineering executables.
---

# Binary Analysis Skill

Use the `re-lab` MCP server tools to analyze executable binaries.

## Quick Start

```
1. re_file_identify(file_path="<path>")
2. re_analyze(agent_type="binary", file_path="<path>")
```

## Full Command Reference

```python
# Quick automated analysis
re_analyze(agent_type="binary", file_path="/path/to/bin", analysis_type="basic")

# Full ELF analysis
re_readelf(file_path="/path/to/bin", all=true)

# Disassemble specific function
re_objdump(file_path="/path/to/bin", start_address="0x401000", end_address="0x401100")

# Strings with filter
re_strings(file_path="/path/to/bin", min_length=8, filter_pattern="http|url|key|pass")

# GDB analysis
re_gdb(binary_path="/path/to/bin", commands=["info functions", "info headers"])

# Symbol table
re_gdb_symbols(binary_path="/path/to/bin", use_nm=true, symbol_type="t")

# CPU registers
re_gdb_registers(binary_path="/path/to/bin")

# Stack backtrace
re_gdb_backtrace(binary_path="/path/to/bin", pre_commands=["break main", "run"])

# Memory inspection
re_gdb_memory(binary_path="/path/to/bin", address="0x7fffffffe000", format="x", count=16)

# Hex dump of header
re_hexdump(file_path="/path/to/bin", length=128)

# Ghidra decompilation
re_ghidra_decompile(file_path="/path/to/bin", address="0x00401000")

# List functions
re_ghidra_functions(file_path="/path/to/bin")

# Cross-references
re_ghidra_xrefs(file_path="/path/to/bin", address="0x00401000")

# Import table
re_ghidra_imports(file_path="/path/to/bin")

# Radare2 (via re_run_command)
re_run_command(command=["radare2", "-q", "-c", "aaa; afl", "/path/to/bin"])
```

## Analysis Checklist

- [ ] File type and architecture identified
- [ ] ELF headers inspected (entry point, sections)
- [ ] Disassembly reviewed (main functions, control flow)
- [ ] Strings extracted (URLs, keys, config, debug info)
- [ ] Security features checked (canary, NX, PIE, RELRO)
- [ ] Dangerous functions identified
- [ ] Findings stored in knowledge base (`kb_add_fact`)

## Security Indicators

- `__stack_chk_fail` → stack canary present
- `NX` in readelf → non-executable stack
- `DYNAMIC` → PIE enabled
- `RELRO: FULL RELRO` → full RELRO
- `system()`, `execve()`, `strcpy()`, `gets()` → dangerous functions
- Hardcoded IPs, URLs, or keys in strings output

## After Analysis

Store findings:
```
kb_add_fact(title="Binary uses AES encryption", description="...", confidence=0.9, tags=["crypto", "aes"])
```

Check for prior findings:
```
kb_search(query="similar binary analysis")
re_rag_search(query="ELF binary encryption patterns")
```

If conflicting with another agent, debate:
```
re_debate(topic="...", assertions=[...])
```
