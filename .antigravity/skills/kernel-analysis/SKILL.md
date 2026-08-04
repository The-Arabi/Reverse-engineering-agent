---
name: kernel-analysis
description: Use when the user wants to analyze kernel modules, drivers, system calls, or OS internals. Triggers on kernel, .ko module, driver, syscall, strace, kernel reverse engineering, or OS internals.
---

# Kernel/OS Analysis Skill

Use the `re-lab` MCP server tools to analyze kernel modules, drivers, and OS internals.

## Quick Start

```
1. re_file_identify(file_path="<target>")
2. re_analyze(agent_type="kernel", file_path="<target>")
```

## Full Command Reference

```python
# Quick automated analysis
re_analyze(agent_type="kernel", file_path="module.ko")

# Full module info
re_readelf(file_path="module.ko", all=true)

# Symbol table
re_gdb_symbols(binary_path="module.ko")
re_readelf(file_path="module.ko", symbols=true)

# Disassembly
re_objdump(file_path="module.ko")

# CPU registers
re_gdb_registers(binary_path="module.ko")

# Stack backtrace
re_gdb_backtrace(binary_path="module.ko")

# Memory inspection
re_gdb_memory(binary_path="module.ko", address="0xffffffff81000000", count=32)

# Syscall tracing
re_run_command(command=["strace", "-f", "-o", "/tmp/trace.log", "./binary"])
re_run_command(command=["strace", "-e", "trace=open,read,write", "./binary"])

# Kernel module analysis
re_run_command(command=["modinfo", "module.ko"])

# Ghidra decompilation of specific function
re_ghidra_decompile(file_path="module.ko", address="0x00100000")
```

## Key Kernel Symbols

| Symbol | Meaning |
|--------|---------|
| `module_init` | Module initialization |
| `module_exit` | Module cleanup |
| `register_chrdev` | Character device registration |
| `misc_register` | Misc device registration |
| `copy_from_user` | Kernel reads userspace |
| `copy_to_user` | Kernel writes to userspace |
| `ioctl` | Device control interface |
| `kmalloc` / `kfree` | Kernel memory allocation |

## Security Analysis

- Kernel module integrity (unsigned modules)
- Privilege escalation vectors
- Device driver vulnerabilities
- Improper access control in ioctls
- Hardcoded credentials in kernel code

## After Analysis

Cross-reference with binary analysis. Store with `kb_add_fact`, link with `kb_link_items`.
Use `re_rag_search` to find similar past analyses.
