---
name: firmware-analysis
description: Use when the user wants to analyze firmware images (routers, IoT, cameras, embedded devices). Triggers on firmware, IoT, embedded, router, binwalk, squashfs, flash image analysis, or firmware extraction.
---

# Firmware Analysis Skill

Use the `re-lab` MCP server tools to analyze embedded firmware images.

## Quick Start

```
1. re_file_identify(file_path="<firmware_image>")
2. re_analyze(agent_type="firmware", file_path="<firmware_image>")
```

## Full Command Reference

```python
# Quick automated analysis
re_analyze(agent_type="firmware", file_path="firmware.bin")

# Scan firmware for embedded components
re_binwalk(file_path="firmware.bin", scan_only=true)

# Extract embedded files
re_binwalk(file_path="firmware.bin", extract=true)

# Search for credentials in extracted filesystem
re_strings(file_path="rootfs/etc/passwd")
re_strings(file_path="rootfs/etc/shadow", min_length=6)

# Examine web interface
re_strings(file_path="rootfs/www/cgi-bin/login.cgi", filter_pattern="password|admin|secret")

# Hex dump of firmware header
re_hexdump(file_path="firmware.bin", length=512)

# Custom extraction tools
re_run_command(command=["unsquashfs", "-d", "rootfs", "squashfs-root"])
re_run_command(command=["jefferson", "-f", "jffs2.bin", "-d", "jffs2-root"])
```

## Common Firmware Formats

| Magic | Format | Notes |
|-------|--------|-------|
| `28cd3d45` | CramFS | Compressed ROM filesystem |
| `hsqs` / `shsq` | SquashFS | Common in routers |
| `8519` | JFFS2 | Flash filesystem |
| `27051956` | uImage | U-Boot boot image |
| `TDMH` | TRX | Broadcom firmware header |

## Security Analysis

Check for:
- Hardcoded root passwords or credentials
- Debug interfaces (telnet, SSH with known keys)
- Default API keys or tokens
- Insecure update mechanisms
- Cryptographic key material
- Upstream URLs and cloud endpoints

## After Analysis

Store findings with `kb_add_fact`. Link to related binary findings with `kb_link_items`.
Use `re_rag_search` to find similar past analyses.
